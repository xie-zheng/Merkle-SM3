//! 为Merkle树中的数据块实现Hash trait
// trait类似于面向对象中的接口
pub fn hash_to_str(hash: &Vec<u8>) -> String {
    let mut result = String::new();
    for num in hash {
        result.push_str(&format!("{:02x}", num));
    }

    result
}

pub trait HashSM3 {
    fn sm3(&self) -> Vec<u8>;

    fn sm3_str(&self) -> String;
}

impl HashSM3 for Vec<u8> {
    fn sm3(&self) -> Vec<u8> {
        crate::sm3::sm3(&self).to_vec()
    }

    fn sm3_str(&self) -> String {
        hash_to_str(&self.sm3())
    }
}
