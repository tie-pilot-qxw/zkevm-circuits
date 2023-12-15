use rand::Rng;
use std::iter;

pub fn gen_random_hex_str(len: usize) -> String {
    const CHARSET: &[u8] = b"0123456789ABCDEF";
    let mut rng = rand::thread_rng();
    let one_char = || CHARSET[rng.gen_range(0..CHARSET.len())] as char;
    let rstr: String = iter::repeat_with(one_char).take(len).collect();
    let prefix: String = "0x".to_string();
    format!("{prefix}{rstr}")
}

#[macro_export]
macro_rules! get_func_name {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        type_name_of(f)
            .rsplit("::")
            .find(|&part| part != "f" && part != "{{closure}}")
            .expect("Short function name")
    }};
}
