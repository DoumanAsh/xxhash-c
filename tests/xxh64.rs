use xxhash_c::{XXH64, xxh64};

use core::mem;
use core::hash::Hasher;

#[test]
fn should_work() {
    let data = b"loli";

    let result1 = xxh64(data, 0);
    assert_ne!(result1, 0);

    //To know about size
    assert_eq!(mem::size_of::<XXH64>(), 88);

    let mut hasher = XXH64::new(0);
    hasher.write(&data[..2]);
    hasher.write(&data[2..]);
    let result2 = hasher.finish();
    assert_eq!(result1, result2);
}
