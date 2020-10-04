use xxhash_c::{XXH3_64, xxh3_64};
use get_random_const::random;

use core::mem;
use core::hash::Hasher;

#[test]
fn should_work() {
    let data = b"loli";

    let result1 = xxh3_64(data);
    assert_ne!(result1, 0);

    //To know about size
    assert_eq!(mem::size_of::<XXH3_64>(), 576);

    let mut hasher = XXH3_64::new();
    hasher.write(&data[..2]);
    hasher.write(&data[2..]);
    let result2 = hasher.finish();
    assert_eq!(result1, result2);
}

#[test]
fn try_reset_policies() {
    const SECRET: &[u8] = &random!([u8; 200]);

    let data = b"loli";

    let mut hasher = XXH3_64::new();
    hasher.write(&data[..2]);
    hasher.write(&data[2..]);
    let result1 = hasher.finish();
    assert_ne!(result1, 0);

    hasher.reset(5);
    hasher.write(&data[..2]);
    hasher.write(&data[2..]);
    let result2 = hasher.finish();
    assert_ne!(result1, result2);

    hasher.reset(0);
    hasher.write(&data[..2]);
    hasher.write(&data[2..]);
    let result3 = hasher.finish();
    assert_eq!(result1, result3);

    hasher.reset(SECRET);
    hasher.write(&data[..2]);
    hasher.write(&data[2..]);
    let result4 = hasher.finish();
    assert_ne!(result3, result4);
    assert_ne!(result2, result4);
    assert_ne!(result1, result4);
}
