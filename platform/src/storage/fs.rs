//! The filesystem abstraction the Simple File System protocol is built on: a
//! tree of named nodes with contents, so FAT stays behind one interface.

use alloc::boxed::Box;
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
    /// Reads into `buf` from `offset`, returning how many bytes were read
    /// (short at end of file).
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> usize;
}

/// A mounted volume.
pub trait FileSystem: Send + Sync {
    /// The volume's root directory.
    fn root(&self) -> Box<dyn FileNode>;
    /// Looks up a normalised, backslash-separated path from the root, matching
    /// each component case-insensitively. The empty path is the root.
    fn open(&self, path: &str) -> Option<Box<dyn FileNode>> {
        let mut node = self.root();
        for component in path.split('\\').filter(|component| !component.is_empty()) {
            if !node.is_dir() {
                return None;
            }
            node = node.child(component)?;
        }
        Some(node)
    }
}
