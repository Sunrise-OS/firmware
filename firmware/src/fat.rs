//! FAT, over the `hadris-fat` implementation.
//!
//! The filesystem itself is hadris-fat's; what this module adds is the two
//! things it needs from a firmware: a device adapter that turns a
//! `BlockDevice` into the byte stream its reader wants, and an implementation of
//! this firmware's `FileSystem` interface on top, so the boot manager and the
//! EFI file protocol above it never see FAT at all.
//!
//! Nodes re-walk the volume from the root on every operation rather than holding
//! a directory cursor. Directory walks on a boot volume are a handful of sectors,
//! a boot loader opens two or three files, and re-walking keeps the node type
//! free of a borrow of the volume it came from - which the `FileSystem` interface
//! does not allow it to hold.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use hadris_fat::sync::{
    FatVolume, FatVolumeBuilder, FatVolumeReadExt, FileEntry, Read, Seek, SeekFrom,
};
use spin::Mutex;

use crate::block::{BlockDevice, BlockError};
use crate::fs::{FileNode, FileSystem};

/// The device adapter: a `BlockDevice` presenting the byte stream hadris-fat
/// reads, which is why it has to serve unaligned reads itself.
struct Adapter {
    device: Arc<dyn BlockDevice>,
    position: u64,
}

impl Adapter {
    fn new(device: Arc<dyn BlockDevice>) -> Self {
        Adapter {
            device,
            position: 0,
        }
    }
}

impl Read for Adapter {
    // `hadris_io::Result<T, E>` is `Result<T, Error<E>>`, so the trait's error
    // type is the *kind*: the error itself is the wrapper the kind goes in.
    type Error = hadris_io::ErrorKind;

    fn read(&mut self, buffer: &mut [u8]) -> hadris_io::Result<usize, Self::Error> {
        let block = self.device.block_size() as u64;
        let mut sector = vec![0u8; block as usize];
        let mut done = 0usize;
        while done < buffer.len() {
            let lba = self.position / block;
            if lba >= self.device.block_count() {
                break;
            }
            let within = (self.position % block) as usize;
            self.device
                .read(lba, &mut sector)
                .map_err(|_| hadris_io::Error::from_kind(hadris_io::ErrorKind::Other))?;
            let take = (buffer.len() - done).min(block as usize - within);
            buffer[done..done + take].copy_from_slice(&sector[within..within + take]);
            done += take;
            self.position += take as u64;
        }
        Ok(done)
    }
}

impl Seek for Adapter {
    type Error = hadris_io::ErrorKind;

    fn seek(&mut self, position: SeekFrom) -> hadris_io::Result<u64, Self::Error> {
        let target = match position {
            SeekFrom::Start(offset) => Some(offset as i128),
            SeekFrom::Current(delta) => Some(self.position as i128 + delta as i128),
            SeekFrom::End(delta) => {
                // The volume's length is its device's length; FAT does not need
                // this, but the trait does.
                let end = self.device.block_count() as i128 * self.device.block_size() as i128;
                Some(end + delta as i128)
            }
        };
        let target =
            target.ok_or_else(|| hadris_io::Error::from_kind(hadris_io::ErrorKind::Other))?;
        if target < 0 {
            return Err(hadris_io::Error::from_kind(
                hadris_io::ErrorKind::InvalidInput,
            ));
        }
        self.position = target as u64;
        Ok(self.position)
    }
}

/// A mounted volume.
pub struct Volume {
    inner: Arc<Inner>,
}

struct Inner {
    /// The volume, behind a mutex: hadris-fat's readers take `&self` but
    /// advance internal state, and the EFI file protocol hands out several
    /// handles onto one volume.
    volume: Mutex<FatVolume<Adapter>>,
}

/// Mounts the FAT volume on `device`, if there is one.
pub fn mount(device: Arc<dyn BlockDevice>) -> Option<Arc<dyn FileSystem>> {
    let volume = match FatVolumeBuilder::new(Adapter::new(device)).open() {
        Ok(volume) => volume,
        Err(error) => {
            crate::println!("[fat] not a mountable volume: {error:?}");
            return None;
        }
    };
    let fat_type = volume.fat_type();
    crate::println!("[fat] mounted a {fat_type} volume");
    Some(Arc::new(Volume {
        inner: Arc::new(Inner {
            volume: Mutex::new(volume),
        }),
    }))
}

impl FileSystem for Volume {
    fn root(&self) -> Box<dyn FileNode> {
        Box::new(Node {
            inner: Arc::clone(&self.inner),
            path: String::new(),
            name: String::new(),
            is_dir: true,
            size: 0,
        })
    }
}

/// A file or directory on a mounted volume.
pub struct Node {
    inner: Arc<Inner>,
    /// Path from the volume root, backslash-separated.
    path: String,
    name: String,
    is_dir: bool,
    size: u64,
}

impl Volume {
    /// Looks up a path relative to the root.
    pub fn open(&self, path: &str) -> Option<Node> {
        lookup(&self.inner, path)
    }
}

/// Walks `path` from the root, returning the node it names.
fn lookup(inner: &Arc<Inner>, path: &str) -> Option<Node> {
    let name = path
        .split(['\\', '/'])
        .filter(|component| !component.is_empty())
        .next_back()
        .unwrap_or("")
        .to_string();

    if path.trim_matches(['\\', '/']).is_empty() {
        return Some(Node {
            inner: Arc::clone(inner),
            path: String::new(),
            name: String::new(),
            is_dir: true,
            size: 0,
        });
    }

    let entry = find(inner, path)?;
    Some(Node {
        inner: Arc::clone(inner),
        path: normalise(path),
        name,
        is_dir: entry.is_directory(),
        size: entry.len(),
    })
}

fn normalise(path: &str) -> String {
    path.split(['\\', '/'])
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>()
        .join("\\")
}

/// Finds the entry a path names, walking one component at a time.
fn find(inner: &Arc<Inner>, path: &str) -> Option<FileEntry> {
    let volume = inner.volume.lock();
    let mut directory = volume.root_dir();
    let components: Vec<&str> = path
        .split(['\\', '/'])
        .filter(|component| !component.is_empty())
        .collect();
    let mut entry = None;

    for (index, component) in components.iter().enumerate() {
        let found = directory
            .entries()
            .filter_map(|item| item.ok())
            .filter_map(|item| item.as_entry().cloned())
            // A directory's size is zero, so nothing here may filter on
            // emptiness: only the name identifies an entry.
            .find(|candidate| candidate.name().eq_ignore_ascii_case(component))?;
        if index + 1 < components.len() {
            directory = directory.open_entry(&found).ok()?;
        }
        entry = Some(found);
    }
    entry
}

impl FileNode for Node {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_dir(&self) -> bool {
        self.is_dir
    }

    fn len(&self) -> u64 {
        self.size
    }

    fn child(&self, name: &str) -> Option<Box<dyn FileNode>> {
        let path = if self.path.is_empty() {
            name.to_string()
        } else {
            alloc::format!("{}\\{}", self.path, name)
        };
        let node = lookup(&self.inner, &path)?;
        Some(Box::new(node))
    }

    fn children(&self) -> Vec<Box<dyn FileNode>> {
        if !self.is_dir {
            return Vec::new();
        }
        let mut children = Vec::new();
        {
            // One lock for the whole listing: the volume is a shared resource,
            // and the entries below are copied out of it before it is released.
            let volume = self.inner.volume.lock();
            let Some(directory) = directory_by_name(&volume, &self.path) else {
                return children;
            };
            for item in directory.entries().filter_map(|item| item.ok()) {
                let Some(entry) = item.as_entry() else {
                    continue;
                };
                let name = entry.name().to_string();
                let path = if self.path.is_empty() {
                    name.clone()
                } else {
                    alloc::format!("{}\\{}", self.path, name)
                };
                children.push(Box::new(Node {
                    inner: Arc::clone(&self.inner),
                    path,
                    name,
                    is_dir: entry.is_directory(),
                    size: entry.len(),
                }) as Box<dyn FileNode>);
            }
        }
        children
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> usize {
        if self.is_dir {
            return 0;
        }
        let entry = match find(&self.inner, &self.path) {
            Some(entry) => entry,
            None => return 0,
        };
        let volume = self.inner.volume.lock();
        let mut reader = match volume.read_file(&entry) {
            Ok(reader) => reader,
            Err(_) => return 0,
        };
        if reader.seek(SeekFrom::Start(offset)).is_err() {
            return 0;
        }
        let mut done = 0usize;
        while done < buffer.len() {
            match reader.read(&mut buffer[done..]) {
                Ok(0) | Err(_) => break,
                Ok(read) => done += read,
            }
        }
        done
    }

    fn dyn_clone(&self) -> Box<dyn FileNode> {
        Box::new(Node {
            inner: Arc::clone(&self.inner),
            path: self.path.clone(),
            name: self.name.clone(),
            is_dir: self.is_dir,
            size: self.size,
        })
    }
}

/// Resolves a directory path to a `FatDir`, with the volume already locked.
fn directory_by_name<'a>(
    volume: &'a FatVolume<Adapter>,
    path: &str,
) -> Option<hadris_fat::sync::FatDir<'a, Adapter>> {
    let mut directory = volume.root_dir();
    for component in path.split('\\').filter(|part| !part.is_empty()) {
        let entry = directory
            .entries()
            .filter_map(|item| item.ok())
            .filter_map(|item| item.as_entry().cloned())
            // A directory's size is zero, so nothing here may filter on
            // emptiness: only the name identifies an entry.
            .find(|candidate| candidate.name().eq_ignore_ascii_case(component))?;
        directory = directory.open_entry(&entry).ok()?;
    }
    Some(directory)
}
