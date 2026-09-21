//! The filesystem abstraction.
//!
//! The boot manager walks paths (`\EFI\BOOT\BOOTAA64.EFI`), and the EFI Simple
//! File System protocol exposes the same files as `EFI_FILE_PROTOCOL` handles.
//! Both speak this: a tree of nodes with names, contents, and sizes, so the
//! FAT implementation stays behind one interface.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

/// A node in a mounted volume: a directory or a file.
pub trait FileNode {
    /// The name as stored, without any path. For the volume root, empty.
    fn name(&self) -> &str;
    /// Whether this node is a directory.
    fn is_dir(&self) -> bool;
    /// The file's size in bytes; 0 for a directory.
    fn len(&self) -> u64;
    /// Opens a child by name, matched case-insensitively, as FAT names are.
    fn child(&self, name: &str) -> Option<Box<dyn FileNode>>;
    /// The children of a directory, in the order the filesystem stores them.
    fn children(&self) -> Vec<Box<dyn FileNode>>;
    /// Reads `buf.len()` bytes at the current position, returning how many were
    /// read (short at end of file).
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> usize;
    /// The whole file's contents, for images and small files.
    fn read_all(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; self.len() as usize];
        let mut node = self.dyn_clone();
        let read = node.read_at(0, &mut buffer);
        buffer.truncate(read);
        buffer
    }
    /// An independent handle on the same node, for readers that need their own
    /// position.
    fn dyn_clone(&self) -> Box<dyn FileNode>;
}

/// A mounted volume.
pub trait FileSystem: Send + Sync {
    /// The volume's root directory.
    fn root(&self) -> Box<dyn FileNode>;
    /// Looks up a path, with `\` or `/` as separators and a case-insensitive
    /// match at each step. Returns `None` if any component is missing.
    fn open(&self, path: &str) -> Option<Box<dyn FileNode>> {
        let mut node: Box<dyn FileNode> = self.root();
        for component in path.split(['\\', '/']) {
            if component.is_empty() || component == "." {
                continue;
            }
            if !node.is_dir() {
                return None;
            }
            node = node.child(component)?;
        }
        Some(node)
    }
}
