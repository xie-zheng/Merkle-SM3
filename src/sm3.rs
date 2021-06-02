pub fn sm3(data: &Vec<u8>) -> [u8; 32] {
    let mut obj = SM3::new(data);
    let hash = obj.hash();
    hash
}

struct SM3 {
    digest: [u32; 8], // 哈希值（初始值、迭代压缩中间值）
    length: u64,      // 原始长度（比特）
    message: Vec<u8>, // 原始或填充后的消息
}

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
fn u8_to_u32(buffer: &[u8], i: usize) -> u32 {
    u32::from(buffer[i]) << 24
        | u32::from(buffer[i + 1]) << 16
        | u32::from(buffer[i + 2]) << 8
        | u32::from(buffer[i + 3])
}

// 把u32整数转化为4个8u整数（大端）并放入指定位置
fn u32_to_u8(buffer: &mut [u8], i: usize, num: u32) {
    for j in (0..4).rev() {
        buffer[i * 4 + 3 - j] = (num >> (j * 8)) as u8;
    }
}

impl SM3 {
    fn new(data: &Vec<u8>) -> SM3 {
        SM3 {
            digest: IV,
            length: (data.len() << 3) as u64,
            message: data.clone(),
        }
    }

    // 设消息m的长度为l比特。首先将比特“1”添加到消息的末尾，再添加k个“0”，k是
    // 满足l + 1 + k == 448mod512的最小的非负整数。然后再添加一个64位比特串，
    // 该比特串是长度l的二进制表示。填充后的消息m′的比特长度为512的倍数。
    fn pad(&mut self) {
        self.message.push(0x80);
        let blocksize = 64;
        // 填充至l + 1 + k == 448mod512
        let mut fill = self.message.len() % blocksize;
        if fill > 56 {
            fill = 120 - fill;
        } else {
            fill = 56 - fill;
        }
        for _ in 0..fill {
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

    fn expand(&mut self, w: &mut [u32; 68], w1: &mut [u32; 64], buffer: &[u8; 64]) {
        // 以大端形式把字节转换为字放入w中
        for i in 0..16 {
            w[i] = u8_to_u32(buffer, i * 4);
        }
        for i in 16..68 {
            w[i] = p1(w[i - 16] ^ w[i - 9] ^ w[i - 3].rotate_left(15))
                ^ w[i - 13].rotate_left(7)
                ^ w[i - 6];
        }
        for i in 0..64 {
            w1[i] = w[i] ^ w[i + 4];
        }
    }

    fn cf(&mut self, buffer: &[u8; 64]) {
        // 消息拓展
        let mut w: [u32; 68] = [0; 68];
        let mut w1: [u32; 64] = [0; 64];
        self.expand(&mut w, &mut w1, buffer);
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

    fn hash(&mut self) -> [u8; 32] {
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
    fn hash_1() {
        let string = String::from("abc");
        //let string = String::from("abcd");

        let s = string.as_bytes().to_vec();

        let hash = sm3(&s);
        let expect_hash = [
            0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10,
            0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b,
            0x8f, 0x4b, 0xa8, 0xe0,
        ];
        assert_eq!(hash, expect_hash);
    }

    #[test]
    fn hash_2() {
        let string =
            String::from("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");

        let s = string.as_bytes().to_vec();

        let hash = sm3(&s);
        let expect_hash = [
            0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e,
            0x5a, 0x4d, 0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3,
            0x9c, 0x0c, 0x57, 0x32,
        ];
        assert_eq!(hash, expect_hash);
    }

    #[test]
    fn pad_1() {
        let string = String::from("abc");
        let string = string.as_bytes().to_vec();

        let mut s = SM3::new(&string);
        s.pad();

        let expect: [u32; 16] = [
            0x61626380, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000018,
        ];
        let mut expect_u8: [u8; 64] = [0; 64];
        for (i, num) in expect.iter().enumerate() {
            u32_to_u8(&mut expect_u8, i, *num);
        }

        for (i, num) in s.message.iter().enumerate() {
            assert_eq!(*num, expect_u8[i]);
        }
    }

    #[test]
    fn pad_2() {
        let string =
            String::from("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
        let string = string.as_bytes().to_vec();

        let mut s = SM3::new(&string);
        s.pad();

        let expect: [u32; 32] = [
            0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364,
            0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364,
            0x61626364, 0x61626364, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000200,
        ];
        let mut expect_u8: [u8; 128] = [0; 128];
        for (i, num) in expect.iter().enumerate() {
            u32_to_u8(&mut expect_u8, i, *num);
        }

        for (i, num) in s.message.iter().enumerate() {
            assert_eq!(*num, expect_u8[i], "panic at pos :{}", i);
        }
    }

    #[test]
    fn expand_1() {
        let string = String::from("abc");
        let s = string.as_bytes().to_vec();
        let mut s = SM3::new(&s);
        s.pad();

        let mut w: [u32; 68] = [0; 68];
        let mut w1: [u32; 64] = [0; 64];
        let mut buffer: [u8; 64] = [0; 64];
        for (i, byte) in s.message.iter().enumerate() {
            buffer[i] = *byte;
        }
        s.expand(&mut w, &mut w1, &buffer);

        let expect_w: [u32; 68] = [
            0x61626380, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000018, 0x9092e200, 0x00000000, 0x000c0606, 0x719c70ed, 0x00000000,
            0x8001801f, 0x939f7da9, 0x00000000, 0x2c6fa1f9, 0xadaaef14, 0x00000000, 0x0001801e,
            0x9a965f89, 0x49710048, 0x23ce86a1, 0xb2d12f1b, 0xe1dae338, 0xf8061807, 0x055d68be,
            0x86cfd481, 0x1f447d83, 0xd9023dbf, 0x185898e0, 0xe0061807, 0x050df55c, 0xcde0104c,
            0xa5b9c955, 0xa7df0184, 0x6e46cd08, 0xe3babdf8, 0x70caa422, 0x0353af50, 0xa92dbca1,
            0x5f33cfd2, 0xe16f6e89, 0xf70fe941, 0xca5462dc, 0x85a90152, 0x76af6296, 0xc922bdb2,
            0x68378cf5, 0x97585344, 0x09008723, 0x86faee74, 0x2ab908b0, 0x4a64bc50, 0x864e6e08,
            0xf07e6590, 0x325c8f78, 0xaccb8011, 0xe11db9dd, 0xb99c0545,
        ];
        let expect_w1: [u32; 64] = [
            0x61626380, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000018, 0x9092e200, 0x00000000,
            0x000c0606, 0x719c70f5, 0x9092e200, 0x8001801f, 0x93937baf, 0x719c70ed, 0x2c6fa1f9,
            0x2dab6f0b, 0x939f7da9, 0x0001801e, 0xb6f9fe70, 0xe4dbef5c, 0x23ce86a1, 0xb2d0af05,
            0x7b4cbcb1, 0xb177184f, 0x2693ee1f, 0x341efb9a, 0xfe9e9ebb, 0x210425b8, 0x1d05f05e,
            0x66c9cc86, 0x1a4988df, 0x14e22df3, 0xbde151b5, 0x47d91983, 0x6b4b3854, 0x2e5aadb4,
            0xd5736d77, 0xa48caed4, 0xc76b71a9, 0xbc89722a, 0x91a5caab, 0xf45c4611, 0x6379de7d,
            0xda9ace80, 0x97c00c1f, 0x3e2d54f3, 0xa263ee29, 0x12f15216, 0x7fafe5b5, 0x4fd853c6,
            0x428e8445, 0xdd3cef14, 0x8f4ee92b, 0x76848be4, 0x18e587c8, 0xe6af3c41, 0x6753d7d5,
            0x49e260d5,
        ];

        assert_eq!(w, expect_w);
        assert_eq!(w1, expect_w1);
    }
}
