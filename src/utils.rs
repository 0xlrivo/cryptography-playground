// dumps logical bits (architecture indipendent) from MSB (63) to LSB (0)
pub fn logical_dump_bits_u64(val: u64) {
    for i in 0..64 {
        if i % 8 == 0 {
            print!(" ");
        }
        print!("{}", (val >> (63-i) & 1));
    }
    println!();
}

pub fn logical_dump_bits_u32(val: u32) {
    for i in 0..32 {
        if i % 8 == 0 {
            print!(" ");
        }
        print!("{}", (val >> (31-i) & 1));
    }
    println!();
}   

pub fn logical_dump_bits_u28(val: u32) {
    for i in 0..28 {
        if i % 8 == 0 {
            print!(" ");
        }
        print!("{}", (val >> (27-i) & 1));
    }
    println!();
}   

// architecture dependend helper that dumps the memory content of an u64 (little or big endian)
pub fn physical_dump_bits_u64(val: u64) {
    let ptr = &val as *const u64 as *const u8;
    
    for i in 0..8 {
        unsafe {
            let byte = *ptr.add(i);
            print!("Byte {}: {:08b} ", i, byte);
        }
    }
    println!();
}
