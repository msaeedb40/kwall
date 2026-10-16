pub struct FlowStorage {
    count: usize,
}

impl FlowStorage {
    pub fn new() -> Self {
        Self { count: 0 }
    }

    pub fn insert(&mut self) {
        self.count += 1;
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for FlowStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage() {
        let mut storage = FlowStorage::new();
        assert!(storage.is_empty());
        storage.insert();
        assert_eq!(storage.len(), 1);
    }
}
