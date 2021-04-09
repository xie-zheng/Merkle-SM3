// message 0~2^64-1 bit
// result  256 bit
// fn sm3(message: ...) -> ... {}
// 初始值
const IV: [u32; 8] = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

// 常量
const T0_15: u32 = 0x79cc4519;
const T16_63: u32 = 0x7a879d8a;

fn get_tt(j: u32) -> u32 {
    if j < 16 {
        T0_15
    } else if j < 64 {
        T16_63
    } else {
        panic!("SM3 get_tt: j out of range 0-63")
    }
}

// 布尔函数
fn ff0_15(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn ff16_63(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn ff(x: u32, y: u32, z: u32, j: u32) -> u32 {
    if j < 16 {
        ff0_15(x, y, z)
    } else if j < 64 {
        ff16_63(x, y, z)
    } else {
        panic!("SM3 ff: j out of range j = {}", j);
    }
}

fn gg0_15(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn gg16_63(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

fn gg(x: u32, y: u32, z: u32, j: u32) -> u32 {
    if j < 16 {
        gg0_15(x, y, z)
    } else if j < 64 {
        gg16_63(x, y, z)
    } else {
        panic!("SM3 gg: j out of range j = {}", j);
    }
}

// 置换函数
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

// 把4个u8整数转化为u32整数(大端)
fn u8_to_u32(buffer: &[u8; 64], i: usize) -> u32 {
    u32::from(buffer[i]) << 24
        | u32::from(buffer[i + 1]) << 16
        | u32::from(buffer[i + 2]) << 8
        | u32::from(buffer[i + 3])
}

// 原来j * 8 写成了j * 3（论单元测试的重要性）
fn u32_to_u8(buffer: &mut [u8; 32], i: usize, num: u32) {
    for j in (0..4).rev() {
        buffer[i * 4 + 3 - j] = (num >> (j * 8)) as u8;
    }
}

pub struct SM3 {
    digest: [u32; 8], // 哈希值
    length: u64,      // 长度（比特）
    message: Vec<u8>, // 原始消息
}

impl SM3 {
    pub fn new(data: &[u8]) -> SM3 {
        let mut hash = SM3 {
            digest: IV,
            length: (data.len() << 3) as u64,
            message: Vec::new(),
        };
        for byte in data.iter() {
            hash.message.push(*byte);
        }
        hash
    }

    // 设消息m的长度为l比特。首先将比特“1”添加到消息的末尾，再添加k个“0”，k是
    // 满足l + 1 + k == 448mod512的最小的非负整数。然后再添加一个64位比特串，
    // 该比特串是长度l的二进制表示。填充后的消息m′的比特长度为512的倍数。
    fn pad(&mut self) {
        self.message.push(0x80);
        let blocksize = 64;
        // 填充至l + 1 + k == 448mod512
        for _ in 0..(56 - self.message.len() % blocksize) {
            self.message.push(0x00);
        }

        // 添加一个64位比特串，该比特串是长度l的二进制表示
        // 以大端将原始长度存入message
        for i in (0..8).rev() {
            self.message.push((self.length >> (i * 8) & 0xff) as u8)
        }

        if self.message.len() % 64 != 0 {
            panic!("SM3::pad : 填充后消息长度有误");
        }
    }

    fn cf(&mut self, buffer: &[u8; 64]) {
        // 消息拓展
        let mut w: [u32; 68] = [0; 68];
        let mut w1: [u32; 64] = [0; 64];

        for i in 0..16 {
            w[i] = u8_to_u32(&buffer, i * 4);
        }
        for i in 16..68 {
            w[i] = p1(w[i - 16] ^ w[i - 9] ^ w[i - 3].rotate_left(15))
                ^ w[i - 13].rotate_left(7)
                ^ w[i - 6];
        }
        for i in 0..64 {
            w1[i] = w[i] ^ w[i + 4];
        }

        // ABCDEFGH <- V
        // 将V复制到r中，使用ABCDEFGH作为索引
        let mut r = self.digest;
        let (a, b, c, d, e, f, g, h) = (0, 1, 2, 3, 4, 5, 6, 7);
        let mut ss1: u32;
        let mut ss2: u32;
        let mut tt1: u32;
        let mut tt2: u32;

        for i in 0..64 {
            ss1 = (r[a]
                .rotate_left(12)
                .wrapping_add(r[e])
                .wrapping_add(get_tt(i).rotate_left(i as u32)))
            .rotate_left(7);
            ss2 = ss1 ^ (r[a].rotate_left(12));
            tt1 = ff(r[a], r[b], r[c], i)
                .wrapping_add(r[d])
                .wrapping_add(ss2)
                .wrapping_add(w1[i as usize]);
            tt2 = gg(r[e], r[f], r[g], i)
                .wrapping_add(r[h])
                .wrapping_add(ss1)
                .wrapping_add(w[i as usize]);
            r[d] = r[c];
            r[c] = r[b].rotate_left(9);
            r[b] = r[a];
            r[a] = tt1;
            r[h] = r[g];
            r[g] = r[f].rotate_left(19);
            r[f] = r[e];
            r[e] = p0(tt2);
        }
        for i in 0..8 {
            self.digest[i] ^= r[i];
        }
    }

    pub fn hash(&mut self) -> [u8; 32] {
        let mut output: [u8; 32] = [0; 32];
        let mut buffer: [u8; 64] = [0; 64];
        // 填充
        self.pad();

        // 将填充后的消息m′按512比特进行分组：m′ = B(0)B(1)...B(n−1)
        // 每次将512比特数据从message存入buffer后使用压缩函数迭代
        for j in 0..(self.message.len() / 64) {
            for i in (j * 64)..(j * 64 + 64) {
                buffer[i - j * 64] = self.message[i];
            }
            self.cf(&buffer);
        }

        // 以字节形式（大端）将散列值输出到output中
        for (i, num) in self.digest.iter().enumerate() {
            u32_to_u8(&mut output, i, *num);
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lets_hash_1() {
        let string = String::from("abc");
        //let string = String::from("abcd");

        let s = string.as_bytes();

        let mut sm3 = SM3::new(s);

        let hash = sm3.hash();

        let standrad_hash: [u8; 32] = [
            0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10,
            0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b,
            0x8f, 0x4b, 0xa8, 0xe0,
        ];

        for i in 0..32 {
            assert_eq!(standrad_hash[i], hash[i]);
        }
    }

    #[test]
    fn lets_hash_2() {
        let string =
            String::from("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");

        let s = string.as_bytes();

        let mut sm3 = SM3::new(s);

        let hash = sm3.hash();

        let standrad_hash: [u8; 32] = [
            0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e,
            0x5a, 0x4d, 0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3,
            0x9c, 0x0c, 0x57, 0x32,
        ];

        for i in 0..32 {
            assert_eq!(standrad_hash[i], hash[i]);
        }
    }
}
