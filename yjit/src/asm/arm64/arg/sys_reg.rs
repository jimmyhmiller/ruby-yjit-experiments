/// The encoded representation of an A64 system register.
/// https://developer.arm.com/documentation/ddi0601/2022-06/AArch64-Registers/
pub enum SystemRegister {
    /// https://developer.arm.com/documentation/ddi0601/2022-06/AArch64-Registers/NZCV--Condition-Flags?lang=en
    NZCV = 0b101_1010_0001_0000,
}
