pub fn bits2num(bits: &[bool]) -> u32 {
    let mut result = 0;

    for &bit in bits {
        result = (result << 1) | (bit as u32);
    }

    result
}

pub fn num2bits(num: u32, bit_count: usize) -> Vec<bool> {
    let mut result = Vec::with_capacity(bit_count);
    let mut num = num;
    for _ in 0..bit_count {
        result.push((num & 1) == 1);
        num >>= 1;
    }

    result.reverse();
    result
}

pub struct SBox {
    table: Vec<Vec<u32>>,
    inverse_table: Vec<Vec<u32>>,
}

impl SBox {
    pub fn new(table: Vec<Vec<u32>>) -> Result<SBox, &'static str> {
        if !Self::check_table(&table) {
            return Err("invalid table");
        }

        Ok(SBox {
            inverse_table: Self::reverse_table(&table),
            table,
        })
    }

    fn check_table(table: &Vec<Vec<u32>>) -> bool {
        let n = table.len();
        if (n == 0) || n != (1 << Self::ceil_log(n)) {
            return false;
        }

        let m = table[0].len();
        if (m == 0) || m != (1 << Self::ceil_log(m)) {
            return false;
        }
        for row in table {
            if row.len() != m {
                return false;
            }
        }

        let result_bits_count = Self::max_bits(&table);
        if result_bits_count != Self::ceil_log(n) + Self::ceil_log(m) {
            return false;
        }


        true
    }

    fn max_bits(table: &Vec<Vec<u32>>) -> usize {
        let mut result_bits_count = 0;
        for row in table {
            for &el in row {
                result_bits_count = std::cmp::max(result_bits_count, Self::ceil_log(el as usize));
            }
        }

        result_bits_count
    }

    fn ceil_log(mut num: usize) -> usize {
        let mut res = 0;
        while num > 1 {
            res += 1;
            num = (num >> 1) + (num & 1);
        }
        res
    }

    pub fn reverse_table(table: &Vec<Vec<u32>>) -> Vec<Vec<u32>> {
        let result_bits_count = Self::max_bits(&table);

        let n = table.len();
        let m = table[0].len();

        let mut result = vec![vec![0; m]; n];
        for i in 0..n {
            for j in 0..m {
                let bits = num2bits(table[i][j], result_bits_count);
                let (outer_bits, middle_bits) = bits.split_at(Self::ceil_log(n));

                result[bits2num(&outer_bits) as usize][bits2num(middle_bits) as usize] =
                    ((i as u32) << Self::ceil_log(m) as u32) | (j as u32);
            }
        }

        result
    }

    fn transform(bits: &[bool], table: &Vec<Vec<u32>>) -> Vec<bool> {
        let outer_bits_count = Self::ceil_log(table.len());

        let (outer_bits, middle_bits) = bits.split_at(outer_bits_count);

        let result_bits_count= Self::max_bits(&table);

        num2bits(
            table[bits2num(outer_bits) as usize][bits2num(middle_bits) as usize],
            result_bits_count,
        )
    }

    pub fn encrypt(&self, bits: &[bool]) -> Vec<bool> {
        Self::transform(bits, &self.table)
    }

    pub fn decrypt(&self, bits: &[bool]) -> Vec<bool> {
        Self::transform(bits, &self.inverse_table)
    }
}

pub struct PBox {
    permutation: Vec<u32>,
    inverse_permutation: Vec<u32>,
}

impl PBox {
    pub fn new(permutation: Vec<u32>) -> Result<PBox, &'static str> {
        if !Self::is_permutation(&permutation) {
            return Err("invalid permutation");
        }

        Ok(PBox {
            inverse_permutation: Self::reverse_permutation(&permutation),
            permutation,
        })
    }

    fn is_permutation(permutation: &[u32]) -> bool {
        let n = permutation.len();
        if !(n <= 32) {
            return false;
        }

        let mut used = 0u32;
        for &num in permutation {
            if n < num.try_into().unwrap() || num == 0 {
                return false;
            }

            let bit_num = 1u32 << (num - 1);
            if (used & bit_num) != 0 {
                return false;
            }

            used |= bit_num;
        }

        true
    }

    fn reverse_permutation(permutation: &[u32]) -> Vec<u32> {
        let mut reverse_permutation = vec![0; permutation.len()];

        for (i, &num) in permutation.iter().enumerate() {
            reverse_permutation[num as usize - 1] = i as u32 + 1;
        }

        reverse_permutation
    }

    fn transform(bits: &[bool], permutation: &[u32]) -> Vec<bool> {
        let n = bits.len();
        let mut result = vec![false; n];
        for i in 0..n {
            result[(permutation[i] - 1) as usize] = bits[i];
        }

        result
    }

    pub fn encrypt(&self, bits: &[bool]) -> Vec<bool> {
        Self::transform(bits, &self.permutation[..])
    }

    pub fn decrypt(&self, bits: &[bool]) -> Vec<bool> {
        Self::transform(bits, &self.inverse_permutation[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ceil_log() {
        assert_eq!(SBox::ceil_log(16), 4);
        assert_eq!(SBox::ceil_log(15), 4);
        assert_eq!(SBox::ceil_log(17), 5);
        assert_eq!(SBox::ceil_log(9), 4);
        assert_eq!(SBox::ceil_log(8), 3);
        assert_eq!(SBox::ceil_log(1), 0);
    }

    #[test]
    fn test1() {
        let table = vec![
            vec![
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
                0xab, 0x76,
            ],
            vec![
                0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
                0x72, 0xc0,
            ],
            vec![
                0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8,
                0x31, 0x15,
            ],
            vec![
                0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27,
                0xb2, 0x75,
            ],
            vec![
                0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
                0x2f, 0x84,
            ],
            vec![
                0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c,
                0x58, 0xcf,
            ],
            vec![
                0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
                0x9f, 0xa8,
            ],
            vec![
                0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
                0xf3, 0xd2,
            ],
            vec![
                0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d,
                0x19, 0x73,
            ],
            vec![
                0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e,
                0x0b, 0xdb,
            ],
            vec![
                0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95,
                0xe4, 0x79,
            ],
            vec![
                0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a,
                0xae, 0x08,
            ],
            vec![
                0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd,
                0x8b, 0x8a,
            ],
            vec![
                0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1,
                0x1d, 0x9e,
            ],
            vec![
                0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
                0x28, 0xdf,
            ],
            vec![
                0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54,
                0xbb, 0x16,
            ],
        ];

        let s_box = SBox::new(table).unwrap();

        let a = 0b11001010;
        let a_bits = num2bits(a, 8);
        let b = s_box.encrypt(&a_bits);
        let c = s_box.decrypt(&b);

        let c_num = bits2num(&c);
        assert_eq!(a, c_num);

        let a = 0b11111111;
        let a_bits = num2bits(a, 8);
        let b = s_box.encrypt(&a_bits);
        let c = s_box.decrypt(&b);

        let c_num = bits2num(&c);
        assert_eq!(a, c_num);
    }

    #[test]
    fn test2() {
        let permutation = vec![4, 2, 7, 1, 3, 8, 5, 6];
        let p_box = PBox::new(permutation).unwrap();

        let a = 0b11001010;
        let a_bits = num2bits(a, 8);
        let b = p_box.encrypt(&a_bits[..]);
        let c = p_box.decrypt(&b);
        let c_num = bits2num(&c);
        assert_eq!(a, c_num);
    }
}
