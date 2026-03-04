//! This integration test defines a set of circuits which are used in order to test the acvm_js package.
//!
//! The acvm_js test suite contains serialized program [circuits][`Program`] which must be kept in sync with the format
//! outputted from the [ACIR crate][acir].
//! Breaking changes to the serialization format then require refreshing acvm_js's test suite.
//! This file contains Rust definitions of these circuits and outputs the updated serialized format.
//!
//! These tests also check this circuit serialization against an expected value, erroring if the serialization changes.
//! Generally in this situation we just need to refresh the `expected_serialization` variables to match the
//! actual output, **HOWEVER** note that this results in a breaking change to the backend ACIR format.

use acir::{
    SerializationFormat,
    circuit::{Circuit, Program, brillig::BrilligBytecode},
    native_types::Witness,
};
use acir_field::FieldElement;
use brillig::{
    BitSize, HeapArray, HeapValueType, HeapVector, IntegerBitSize, MemoryAddress, ValueOrArray,
    lengths::{SemanticLength, SemiFlattenedLength},
};

fn assert_deserialization(expected: &Program<FieldElement>, bytes: [Vec<u8>; 2]) {
    for (i, bytes) in bytes.iter().enumerate() {
        let program = Program::deserialize_program(bytes)
            .map_err(|e| format!("failed to deserialize format {i}: {e:?}"))
            .unwrap();
        assert_eq!(&program, expected, "incorrect deserialized program for format {i}");
    }
}

#[test]
fn addition_circuit() {
    let src = "
    private parameters: [w1, w2]
    public parameters: []
    return values: [w3]
    ASSERT 0 = w1 + w2 - w3
    ";
    let mut circuit = Circuit::from_str(src).unwrap();
    circuit.current_witness_index = 4;

    let program = Program { functions: vec![circuit], unconstrained_functions: vec![] };

    let bytes_msgpack =
        Program::serialize_program_with_format(&program, SerializationFormat::Msgpack);
    insta::assert_compact_debug_snapshot!(bytes_msgpack, @"[31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 141, 144, 191, 74, 3, 65, 16, 198, 239, 46, 62, 136, 165, 118, 138, 79, 32, 34, 88, 137, 165, 8, 50, 108, 246, 70, 93, 184, 157, 93, 103, 118, 163, 150, 167, 141, 229, 93, 242, 2, 1, 11, 73, 32, 136, 138, 255, 122, 95, 36, 157, 165, 141, 189, 75, 64, 177, 50, 153, 106, 24, 62, 62, 230, 247, 43, 46, 71, 71, 145, 116, 48, 142, 164, 189, 158, 252, 236, 64, 202, 226, 240, 73, 71, 102, 164, 0, 103, 38, 16, 138, 128, 161, 18, 207, 151, 110, 157, 215, 174, 68, 105, 235, 241, 166, 8, 114, 56, 64, 118, 87, 35, 27, 43, 8, 200, 86, 154, 199, 202, 16, 42, 6, 237, 108, 215, 144, 154, 149, 15, 250, 239, 203, 217, 255, 147, 231, 11, 100, 138, 148, 89, 43, 119, 121, 186, 62, 92, 125, 221, 219, 126, 174, 235, 253, 195, 149, 141, 143, 157, 139, 55, 223, 110, 77, 191, 6, 159, 41, 212, 185, 57, 5, 61, 183, 42, 123, 240, 108, 122, 42, 32, 120, 197, 9, 55, 253, 46, 253, 188, 184, 247, 177, 91, 25, 253, 231, 216, 76, 24, 67, 100, 130, 158, 170, 98, 194, 238, 220, 169, 25, 54, 216, 228, 68, 29, 163, 52, 99, 138, 22, 252, 137, 18, 148, 236, 37, 41, 76, 188, 129, 85, 146, 80, 194, 175, 221, 230, 27, 249, 148, 75, 218, 107, 1, 0, 0]");

    let bytes_default = Program::serialize_program(&program);
    insta::assert_compact_debug_snapshot!(bytes_default, @"[31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 141, 204, 59, 14, 64, 48, 0, 128, 225, 62, 28, 196, 200, 70, 156, 64, 68, 98, 18, 163, 72, 108, 58, 147, 214, 98, 236, 13, 250, 88, 140, 157, 29, 64, 216, 93, 164, 155, 209, 98, 215, 19, 224, 159, 191, 252, 88, 201, 217, 120, 146, 47, 41, 99, 132, 142, 13, 161, 189, 22, 90, 29, 62, 120, 15, 194, 31, 6, 57, 19, 117, 37, 181, 177, 9, 183, 42, 95, 57, 175, 219, 32, 57, 139, 105, 31, 100, 102, 111, 125, 57, 132, 63, 55, 64, 65, 36, 36, 22, 64, 60, 98, 17, 206, 26, 173, 0, 0, 0]");

    assert_deserialization(&program, [bytes_msgpack, bytes_default]);
}

#[test]
fn multi_scalar_mul_circuit() {
    let src = "
    private parameters: [w1, w2, w3, w4, w5, w6]
    public parameters: []
    return values: [w7, w8, w9]
    BLACKBOX::MULTI_SCALAR_MUL points: [w1, w2, w3], scalars: [w4, w5], predicate: w6, outputs: [w7, w8, w9]
    ";
    let mut circuit = Circuit::from_str(src).unwrap();
    circuit.current_witness_index = 10;

    let program = Program { functions: vec![circuit], unconstrained_functions: vec![] };

    let bytes_msgpack =
        Program::serialize_program_with_format(&program, SerializationFormat::Msgpack);
    insta::assert_compact_debug_snapshot!(bytes_msgpack, @"[31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 77, 144, 75, 75, 3, 65, 16, 132, 205, 230, 225, 227, 103, 69, 240, 230, 201, 131, 199, 161, 157, 109, 117, 112, 182, 103, 232, 238, 137, 185, 174, 120, 240, 184, 81, 240, 236, 201, 37, 66, 124, 129, 248, 247, 50, 36, 100, 200, 237, 163, 138, 42, 186, 171, 122, 88, 94, 39, 178, 234, 2, 201, 226, 105, 181, 99, 67, 208, 224, 219, 159, 77, 204, 72, 106, 238, 157, 18, 138, 24, 71, 53, 206, 79, 250, 16, 109, 168, 81, 22, 237, 247, 212, 131, 189, 155, 134, 249, 89, 206, 157, 130, 247, 237, 231, 121, 242, 234, 46, 44, 120, 224, 140, 143, 239, 49, 56, 82, 121, 105, 251, 203, 109, 199, 160, 80, 85, 104, 216, 203, 38, 32, 207, 69, 26, 21, 26, 47, 35, 99, 237, 44, 40, 22, 109, 210, 135, 164, 49, 229, 222, 195, 163, 227, 223, 200, 110, 150, 93, 19, 129, 243, 213, 138, 44, 175, 131, 106, 56, 26, 79, 126, 98, 186, 242, 206, 238, 25, 221, 138, 81, 19, 147, 153, 129, 79, 184, 137, 127, 129, 8, 178, 154, 38, 247, 194, 13, 74, 247, 65, 169, 49, 241, 22, 4, 229, 224, 63, 255, 149, 151, 81, 6, 71, 88, 155, 50, 85, 183, 6, 170, 116, 92, 40, 56, 1, 0, 0]");

    let bytes_default = Program::serialize_program(&program);
    insta::assert_compact_debug_snapshot!(bytes_default, @"[31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 61, 198, 187, 14, 64, 48, 20, 0, 80, 212, 251, 179, 72, 108, 38, 131, 185, 105, 12, 226, 166, 18, 109, 19, 107, 255, 160, 15, 17, 163, 205, 38, 62, 17, 203, 221, 14, 113, 246, 56, 75, 171, 159, 10, 40, 155, 170, 121, 109, 20, 103, 53, 5, 208, 119, 171, 64, 142, 29, 163, 64, 151, 143, 155, 215, 87, 63, 74, 62, 8, 17, 162, 34, 20, 113, 200, 24, 149, 160, 82, 159, 229, 197, 30, 70, 36, 78, 82, 243, 219, 4, 230, 5, 240, 160, 204, 250, 123, 0, 0, 0]");

    assert_deserialization(&program, [bytes_msgpack, bytes_default]);
}

#[test]
fn simple_brillig_foreign_call() {
    let w_input = Witness(1);
    let w_inverted = Witness(2);

    let value_address = MemoryAddress::direct(0);
    let zero_usize = MemoryAddress::direct(1);
    let one_usize = MemoryAddress::direct(2);

    let brillig_bytecode = BrilligBytecode {
        function_name: "invert_call".into(),
        bytecode: vec![
            brillig::Opcode::Const {
                destination: zero_usize,
                bit_size: BitSize::Integer(IntegerBitSize::U32),
                value: FieldElement::from(0_usize),
            },
            brillig::Opcode::Const {
                destination: one_usize,
                bit_size: BitSize::Integer(IntegerBitSize::U32),
                value: FieldElement::from(1_usize),
            },
            brillig::Opcode::CalldataCopy {
                destination_address: value_address,
                size_address: one_usize,
                offset_address: zero_usize,
            },
            brillig::Opcode::ForeignCall {
                function: "invert".into(),
                destinations: vec![ValueOrArray::MemoryAddress(value_address)],
                destination_value_types: vec![HeapValueType::field()],
                inputs: vec![ValueOrArray::MemoryAddress(value_address)],
                input_value_types: vec![HeapValueType::field()],
            },
            brillig::Opcode::Stop {
                return_data: HeapVector { pointer: zero_usize, size: one_usize },
            },
        ],
    };

    let src = format!(
        "
    private parameters: [{w_input}, {w_inverted}]
    public parameters: []
    return values: []
    BRILLIG CALL func: 0, predicate: 1, inputs: [{w_input}], outputs: [{w_inverted}]
    "
    );
    let mut circuit = Circuit::from_str(&src).unwrap();
    circuit.current_witness_index = 8;

    let program =
        Program { functions: vec![circuit], unconstrained_functions: vec![brillig_bytecode] };

    let bytes_msgpack =
        Program::serialize_program_with_format(&program, SerializationFormat::Msgpack);
    insta::assert_compact_debug_snapshot!(bytes_msgpack, @"[31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 165, 146, 207, 110, 19, 49, 16, 198, 119, 247, 196, 99, 240, 12, 240, 4, 16, 84, 137, 3, 167, 138, 179, 229, 216, 147, 101, 36, 175, 109, 198, 227, 64, 184, 109, 2, 18, 199, 180, 18, 119, 68, 155, 127, 108, 2, 42, 21, 234, 11, 240, 96, 120, 211, 38, 13, 145, 72, 144, 216, 211, 106, 108, 127, 223, 204, 111, 190, 98, 184, 232, 69, 171, 24, 157, 13, 103, 31, 87, 155, 127, 97, 101, 5, 159, 127, 170, 72, 4, 150, 197, 27, 100, 11, 33, 8, 180, 26, 222, 62, 152, 57, 175, 156, 134, 112, 86, 55, 79, 9, 141, 193, 178, 35, 141, 121, 255, 5, 117, 54, 69, 235, 35, 167, 147, 233, 41, 218, 210, 192, 104, 81, 69, 35, 24, 168, 10, 227, 107, 131, 22, 36, 9, 229, 170, 46, 90, 121, 107, 121, 254, 235, 97, 118, 248, 203, 243, 139, 215, 66, 29, 189, 150, 205, 92, 228, 173, 119, 229, 13, 20, 11, 79, 160, 81, 73, 62, 218, 198, 248, 159, 44, 242, 31, 158, 176, 159, 228, 132, 151, 148, 248, 36, 189, 112, 158, 23, 87, 62, 118, 13, 170, 157, 226, 120, 69, 192, 145, 172, 232, 75, 19, 33, 140, 191, 203, 16, 128, 88, 84, 137, 161, 44, 83, 225, 171, 141, 149, 240, 175, 100, 128, 144, 221, 36, 228, 169, 5, 38, 153, 250, 210, 226, 126, 27, 195, 63, 183, 209, 160, 237, 183, 34, 42, 177, 158, 119, 7, 12, 237, 14, 62, 213, 147, 78, 251, 120, 212, 164, 125, 240, 221, 56, 245, 244, 25, 18, 40, 206, 231, 93, 100, 17, 240, 29, 212, 179, 231, 150, 161, 4, 186, 120, 249, 248, 209, 100, 221, 213, 113, 160, 135, 164, 139, 255, 146, 206, 235, 101, 155, 24, 45, 89, 118, 156, 31, 140, 174, 119, 28, 132, 212, 154, 18, 167, 141, 83, 182, 108, 93, 246, 171, 197, 55, 215, 235, 5, 224, 253, 122, 94, 55, 39, 142, 0, 75, 219, 26, 124, 152, 111, 8, 78, 111, 225, 45, 119, 140, 82, 80, 86, 47, 160, 114, 52, 120, 178, 231, 120, 179, 219, 206, 122, 34, 193, 3, 15, 247, 201, 154, 156, 32, 24, 189, 205, 250, 95, 100, 174, 214, 231, 7, 4, 234, 203, 83, 118, 190, 110, 238, 194, 210, 226, 24, 206, 188, 195, 196, 147, 182, 3, 93, 174, 33, 111, 198, 254, 13, 79, 220, 88, 78, 175, 3, 0, 0]");

    let bytes_default = Program::serialize_program(&program);
    insta::assert_compact_debug_snapshot!(bytes_default, @"[31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 149, 144, 65, 10, 194, 48, 16, 69, 155, 186, 241, 24, 158, 65, 79, 160, 21, 193, 133, 171, 226, 90, 74, 59, 148, 64, 154, 148, 52, 8, 93, 230, 6, 73, 106, 193, 165, 160, 173, 139, 234, 45, 60, 152, 150, 98, 10, 46, 172, 206, 122, 254, 155, 55, 127, 100, 244, 241, 52, 214, 178, 89, 112, 76, 8, 142, 189, 128, 144, 131, 163, 101, 237, 99, 26, 19, 40, 148, 54, 143, 137, 243, 125, 16, 26, 92, 233, 136, 73, 74, 192, 45, 148, 26, 38, 26, 228, 42, 165, 28, 109, 26, 76, 247, 192, 197, 46, 124, 121, 149, 178, 242, 24, 205, 68, 33, 235, 37, 230, 16, 10, 36, 175, 107, 42, 32, 6, 126, 222, 206, 166, 195, 18, 159, 121, 247, 191, 60, 146, 183, 182, 158, 40, 16, 129, 199, 210, 220, 98, 156, 158, 103, 197, 154, 21, 227, 128, 99, 218, 6, 202, 186, 123, 66, 203, 251, 6, 18, 198, 243, 121, 20, 113, 200, 50, 155, 183, 229, 84, 43, 12, 36, 250, 117, 79, 94, 124, 193, 82, 109, 250, 171, 111, 143, 39, 190, 28, 81, 109, 214, 1, 0, 0]");

    assert_deserialization(&program, [bytes_msgpack, bytes_default]);
}

#[test]
fn complex_brillig_foreign_call() {
    let a = Witness(1);
    let b = Witness(2);
    let c = Witness(3);

    let a_times_2 = Witness(4);
    let b_times_3 = Witness(5);
    let c_times_4 = Witness(6);
    let a_plus_b_plus_c = Witness(7);
    let a_plus_b_plus_c_times_2 = Witness(8);

    let brillig_bytecode = BrilligBytecode {
        function_name: "complex_call".into(),
        bytecode: vec![
            brillig::Opcode::Const {
                destination: MemoryAddress::direct(0),
                bit_size: BitSize::Integer(IntegerBitSize::U32),
                value: FieldElement::from(3_usize),
            },
            brillig::Opcode::Const {
                destination: MemoryAddress::direct(1),
                bit_size: BitSize::Integer(IntegerBitSize::U32),
                value: FieldElement::from(0_usize),
            },
            brillig::Opcode::CalldataCopy {
                destination_address: MemoryAddress::direct(32),
                size_address: MemoryAddress::direct(0),
                offset_address: MemoryAddress::direct(1),
            },
            brillig::Opcode::Const {
                destination: MemoryAddress::direct(0),
                value: FieldElement::from(32_usize),
                bit_size: BitSize::Integer(IntegerBitSize::U32),
            },
            brillig::Opcode::Const {
                destination: MemoryAddress::direct(3),
                bit_size: BitSize::Integer(IntegerBitSize::U32),
                value: FieldElement::from(1_usize),
            },
            brillig::Opcode::Const {
                destination: MemoryAddress::direct(4),
                bit_size: BitSize::Integer(IntegerBitSize::U32),
                value: FieldElement::from(3_usize),
            },
            brillig::Opcode::CalldataCopy {
                destination_address: MemoryAddress::direct(1),
                size_address: MemoryAddress::direct(3),
                offset_address: MemoryAddress::direct(4),
            },
            // Oracles are named 'foreign calls' in brillig
            brillig::Opcode::ForeignCall {
                function: "complex".into(),
                inputs: vec![
                    ValueOrArray::HeapArray(HeapArray {
                        pointer: MemoryAddress::direct(0),
                        size: SemiFlattenedLength(3),
                    }),
                    ValueOrArray::MemoryAddress(MemoryAddress::direct(1)),
                ],
                input_value_types: vec![
                    HeapValueType::Array {
                        size: SemanticLength(3),
                        value_types: vec![HeapValueType::field()],
                    },
                    HeapValueType::field(),
                ],
                destinations: vec![
                    ValueOrArray::HeapArray(HeapArray {
                        pointer: MemoryAddress::direct(0),
                        size: SemiFlattenedLength(3),
                    }),
                    ValueOrArray::MemoryAddress(MemoryAddress::direct(35)),
                    ValueOrArray::MemoryAddress(MemoryAddress::direct(36)),
                ],
                destination_value_types: vec![
                    HeapValueType::Array {
                        size: SemanticLength(3),
                        value_types: vec![HeapValueType::field()],
                    },
                    HeapValueType::field(),
                    HeapValueType::field(),
                ],
            },
            brillig::Opcode::Const {
                destination: MemoryAddress::direct(0),
                bit_size: BitSize::Integer(IntegerBitSize::U32),
                value: FieldElement::from(32_usize),
            },
            brillig::Opcode::Const {
                destination: MemoryAddress::direct(1),
                bit_size: BitSize::Integer(IntegerBitSize::U32),
                value: FieldElement::from(5_usize),
            },
            brillig::Opcode::Stop {
                return_data: HeapVector {
                    pointer: MemoryAddress::direct(0),
                    size: MemoryAddress::direct(1),
                },
            },
        ],
    };

    let src = format!("
    private parameters: [{a}, {b}, {c}]
    public parameters: []
    return values: []
    BRILLIG CALL func: 0, predicate: 1, inputs: [[{a}, {b}, {c}], {a} + {b} + {c}], outputs: [[{a_times_2}, {b_times_3}, {c_times_4}], {a_plus_b_plus_c}, {a_plus_b_plus_c_times_2}]
    ");
    let circuit = Circuit::from_str(&src).unwrap();
    let program =
        Program { functions: vec![circuit], unconstrained_functions: vec![brillig_bytecode] };

    let bytes_msgpack =
        Program::serialize_program_with_format(&program, SerializationFormat::Msgpack);
    insta::assert_compact_debug_snapshot!(bytes_msgpack, @"[31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 197, 85, 221, 110, 211, 48, 24, 77, 154, 14, 246, 24, 149, 224, 9, 224, 9, 70, 209, 4, 23, 92, 77, 92, 91, 110, 242, 181, 88, 114, 108, 99, 59, 99, 225, 206, 45, 72, 92, 246, 231, 146, 27, 196, 214, 166, 37, 45, 104, 76, 104, 47, 192, 131, 225, 148, 166, 164, 19, 109, 163, 117, 63, 185, 114, 62, 37, 223, 57, 223, 241, 57, 118, 165, 61, 105, 70, 204, 215, 132, 51, 213, 251, 52, 203, 215, 136, 225, 16, 190, 252, 242, 35, 41, 129, 105, 244, 142, 104, 6, 74, 33, 194, 2, 56, 217, 79, 184, 240, 121, 0, 170, 103, 210, 103, 146, 80, 74, 90, 117, 76, 233, 135, 175, 36, 112, 70, 132, 137, 72, 171, 190, 25, 30, 72, 137, 227, 65, 103, 18, 70, 20, 105, 144, 161, 234, 94, 80, 194, 0, 75, 228, 243, 176, 65, 24, 254, 11, 217, 255, 93, 115, 54, 63, 174, 123, 250, 22, 249, 91, 63, 115, 110, 2, 170, 114, 119, 80, 94, 57, 40, 51, 58, 34, 172, 69, 97, 27, 228, 160, 140, 144, 101, 20, 184, 57, 234, 9, 143, 116, 102, 134, 65, 110, 134, 234, 222, 131, 108, 156, 80, 80, 120, 152, 47, 246, 39, 66, 66, 64, 124, 172, 183, 142, 216, 45, 5, 235, 254, 20, 146, 28, 219, 118, 72, 96, 105, 77, 108, 251, 169, 129, 91, 241, 206, 69, 212, 160, 196, 47, 84, 187, 51, 9, 58, 146, 12, 29, 99, 26, 129, 234, 254, 192, 74, 129, 212, 40, 180, 78, 199, 45, 91, 248, 198, 162, 16, 137, 55, 88, 129, 114, 46, 109, 48, 44, 7, 45, 177, 37, 22, 160, 127, 153, 105, 175, 102, 102, 106, 25, 219, 177, 78, 144, 111, 35, 49, 110, 196, 26, 178, 168, 124, 54, 195, 122, 246, 119, 39, 181, 177, 209, 139, 129, 204, 232, 57, 145, 224, 107, 103, 220, 32, 26, 41, 242, 30, 76, 242, 146, 105, 104, 129, 60, 125, 253, 244, 201, 112, 78, 107, 235, 188, 222, 166, 214, 238, 78, 173, 29, 51, 205, 130, 29, 96, 141, 235, 92, 196, 157, 139, 2, 2, 194, 65, 32, 173, 80, 57, 82, 109, 154, 161, 92, 173, 58, 223, 121, 179, 169, 64, 95, 173, 187, 183, 167, 71, 109, 83, 107, 111, 167, 214, 27, 89, 87, 119, 220, 197, 242, 82, 187, 255, 149, 218, 91, 35, 117, 213, 164, 135, 92, 2, 105, 177, 12, 224, 227, 56, 119, 107, 178, 48, 234, 180, 128, 100, 163, 58, 121, 1, 88, 204, 227, 218, 78, 4, 39, 118, 16, 185, 220, 151, 179, 12, 215, 51, 179, 87, 16, 114, 25, 31, 172, 226, 60, 90, 83, 127, 124, 89, 28, 101, 174, 6, 210, 177, 128, 229, 177, 208, 78, 11, 197, 94, 126, 46, 12, 15, 9, 208, 96, 129, 184, 82, 91, 125, 91, 94, 56, 215, 38, 238, 158, 207, 91, 20, 169, 245, 175, 75, 237, 126, 92, 189, 91, 202, 247, 204, 217, 145, 230, 194, 164, 139, 211, 48, 243, 224, 26, 9, 151, 128, 127, 0, 31, 0, 122, 165, 54, 8, 0, 0]");

    let bytes_default = Program::serialize_program(&program);
    insta::assert_compact_debug_snapshot!(bytes_default, @"[31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 173, 82, 219, 74, 195, 48, 24, 78, 150, 77, 247, 24, 5, 125, 2, 125, 130, 89, 25, 122, 225, 213, 240, 90, 74, 27, 74, 32, 107, 74, 154, 11, 123, 153, 55, 200, 65, 65, 240, 70, 208, 110, 200, 230, 91, 248, 96, 90, 49, 29, 219, 212, 54, 216, 92, 229, 244, 29, 254, 255, 255, 144, 209, 15, 79, 99, 45, 87, 103, 156, 80, 74, 210, 48, 162, 244, 14, 24, 89, 77, 56, 143, 74, 107, 149, 54, 239, 1, 248, 123, 65, 216, 250, 5, 116, 35, 26, 244, 69, 132, 218, 137, 228, 98, 70, 178, 148, 98, 171, 108, 151, 18, 187, 184, 239, 199, 152, 117, 205, 31, 142, 14, 106, 147, 243, 156, 226, 67, 183, 25, 91, 165, 218, 85, 44, 28, 32, 165, 20, 208, 102, 29, 179, 26, 118, 123, 19, 127, 14, 246, 81, 86, 33, 203, 10, 97, 229, 226, 156, 112, 28, 11, 32, 151, 151, 153, 192, 41, 230, 207, 215, 167, 39, 173, 188, 104, 23, 15, 253, 240, 64, 174, 235, 124, 37, 145, 136, 66, 150, 151, 13, 77, 176, 241, 211, 16, 255, 207, 105, 176, 139, 71, 126, 248, 61, 253, 161, 111, 167, 126, 174, 20, 110, 252, 52, 196, 171, 41, 227, 152, 164, 89, 13, 184, 95, 126, 207, 203, 202, 215, 11, 28, 229, 95, 65, 48, 77, 19, 144, 124, 187, 194, 115, 198, 203, 73, 146, 112, 92, 20, 238, 225, 232, 151, 251, 99, 151, 37, 163, 93, 128, 170, 41, 193, 52, 65, 219, 199, 237, 147, 241, 210, 134, 166, 163, 70, 207, 19, 245, 204, 222, 72, 190, 204, 4, 203, 181, 217, 207, 218, 7, 236, 234, 181, 246, 4, 5, 0, 0]");

    assert_deserialization(&program, [bytes_msgpack, bytes_default]);
}

#[test]
fn memory_op_circuit() {
    let src = "
    private parameters: [w1, w2, w3]
    public parameters: []
    return values: [w4]
    INIT b0 = [w1, w2]
    WRITE b0[1] = w3
    READ w4 = b0[1]
    ";
    let mut circuit = Circuit::from_str(src).unwrap();
    circuit.current_witness_index = 5;

    let program = Program { functions: vec![circuit], unconstrained_functions: vec![] };

    let bytes_msgpack =
        Program::serialize_program_with_format(&program, SerializationFormat::Msgpack);
    insta::assert_compact_debug_snapshot!(bytes_msgpack, @"[31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 205, 147, 75, 78, 195, 48, 16, 134, 211, 180, 220, 131, 235, 176, 64, 28, 97, 228, 56, 3, 88, 196, 15, 102, 236, 66, 151, 109, 54, 44, 147, 246, 2, 136, 103, 19, 169, 66, 128, 16, 23, 224, 96, 152, 68, 60, 86, 180, 11, 132, 234, 141, 237, 153, 209, 255, 127, 26, 205, 164, 179, 230, 48, 24, 233, 149, 53, 92, 95, 172, 62, 223, 96, 132, 198, 203, 23, 25, 136, 208, 120, 56, 83, 222, 32, 51, 40, 147, 227, 249, 206, 189, 117, 210, 230, 200, 139, 105, 187, 143, 218, 210, 100, 207, 40, 95, 46, 179, 194, 202, 19, 80, 121, 114, 163, 226, 127, 62, 72, 219, 62, 226, 39, 14, 239, 250, 194, 233, 178, 191, 15, 220, 236, 187, 252, 202, 186, 178, 177, 14, 73, 124, 56, 151, 141, 14, 5, 120, 36, 205, 213, 115, 161, 12, 10, 2, 105, 117, 166, 76, 151, 230, 234, 250, 20, 228, 219, 110, 242, 251, 25, 220, 118, 168, 127, 37, 54, 22, 69, 192, 117, 98, 245, 124, 189, 210, 112, 35, 195, 228, 223, 250, 148, 108, 105, 159, 70, 155, 209, 63, 57, 82, 99, 225, 17, 156, 160, 56, 176, 209, 147, 23, 131, 116, 248, 232, 66, 86, 40, 249, 35, 90, 173, 8, 125, 32, 3, 29, 33, 215, 163, 7, 193, 140, 228, 65, 199, 177, 22, 71, 200, 85, 107, 130, 6, 119, 44, 24, 57, 121, 141, 91, 16, 65, 61, 137, 72, 159, 195, 215, 130, 84, 239, 248, 48, 61, 232, 46, 3, 0, 0]");

    let bytes_default = Program::serialize_program(&program);
    insta::assert_compact_debug_snapshot!(bytes_default, @"[31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 173, 142, 187, 9, 128, 64, 16, 68, 119, 111, 207, 62, 108, 199, 64, 172, 194, 192, 192, 15, 98, 98, 120, 29, 236, 39, 49, 52, 18, 177, 14, 11, 51, 184, 220, 59, 193, 73, 134, 129, 7, 243, 72, 101, 219, 11, 11, 87, 221, 246, 227, 188, 86, 67, 183, 24, 40, 186, 35, 238, 112, 198, 110, 38, 5, 51, 230, 187, 132, 247, 96, 38, 36, 154, 166, 40, 137, 192, 103, 63, 248, 209, 207, 103, 188, 161, 35, 22, 207, 192, 15, 220, 228, 123, 201, 105, 1, 0, 0]");

    assert_deserialization(&program, [bytes_msgpack, bytes_default]);
}

#[test]
fn nested_acir_call_circuit() {
    // Circuit for the following program:
    // fn main(x: Field, y: pub Field) {
    //     let z = nested_call(x, y);
    //     let z2 = nested_call(x, y);
    //     assert(z == z2);
    // }
    // #[fold]
    // fn nested_call(x: Field, y: Field) -> Field {
    //     inner_call(x + 2, y)
    // }
    // #[fold]
    // fn inner_call(x: Field, y: Field) -> Field {
    //     assert(x == y);
    //     x
    // }
    let src = "
    private parameters: [w0]
    public parameters: [w1]
    return values: []
    CALL func: 1, predicate: 1, inputs: [w0, w1], outputs: [w2]
    CALL func: 1, predicate: 1, inputs: [w0, w1], outputs: [w3]
    ASSERT 0 = w2 - w3
    ";
    let main = Circuit::from_str(src).unwrap();

    let src = "
    private parameters: [w0, w1]
    public parameters: []
    return values: [w3]
    ASSERT 0 = w0 - w2 + 2
    CALL func: 2, predicate: 1, inputs: [w2, w1], outputs: [w3]
    ";
    let nested_call = Circuit::from_str(src).unwrap();

    let src = "
    private parameters: [w0, w1]
    public parameters: []
    return values: [w0]
    ASSERT 0 = w0 - w1
    ";
    let inner_call = Circuit::from_str(src).unwrap();

    let program =
        Program { functions: vec![main, nested_call, inner_call], unconstrained_functions: vec![] };

    let bytes_msgpack =
        Program::serialize_program_with_format(&program, SerializationFormat::Msgpack);
    insta::assert_compact_debug_snapshot!(bytes_msgpack,  @"[31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 197, 148, 203, 74, 3, 49, 20, 134, 51, 153, 23, 113, 169, 59, 197, 39, 144, 34, 184, 18, 151, 34, 72, 72, 51, 71, 13, 204, 100, 226, 73, 82, 117, 89, 117, 225, 114, 102, 250, 2, 69, 197, 210, 66, 17, 21, 111, 123, 95, 164, 59, 151, 110, 220, 27, 11, 245, 130, 210, 142, 50, 98, 86, 135, 195, 225, 92, 254, 239, 39, 116, 191, 187, 225, 148, 176, 50, 85, 166, 117, 212, 31, 197, 76, 241, 4, 218, 215, 194, 33, 130, 178, 108, 71, 90, 5, 198, 48, 169, 34, 216, 13, 59, 169, 22, 105, 4, 166, 213, 60, 173, 241, 56, 62, 60, 150, 81, 112, 38, 149, 118, 214, 20, 36, 232, 164, 206, 190, 134, 57, 237, 106, 132, 72, 10, 110, 225, 160, 155, 184, 152, 89, 192, 196, 100, 87, 177, 84, 192, 145, 137, 52, 169, 75, 197, 135, 147, 179, 147, 109, 38, 30, 166, 200, 248, 23, 140, 159, 23, 86, 63, 175, 183, 96, 12, 160, 93, 3, 76, 39, 181, 44, 138, 201, 253, 168, 175, 153, 141, 150, 113, 48, 215, 158, 185, 91, 89, 188, 105, 54, 87, 215, 167, 231, 31, 151, 246, 238, 117, 94, 27, 60, 183, 158, 124, 81, 88, 106, 53, 114, 169, 81, 54, 252, 165, 76, 115, 244, 168, 252, 94, 38, 39, 23, 218, 213, 99, 41, 62, 230, 130, 62, 130, 117, 168, 88, 131, 199, 14, 76, 118, 206, 135, 23, 177, 196, 227, 228, 155, 62, 209, 83, 46, 97, 122, 139, 27, 48, 228, 135, 252, 139, 170, 245, 33, 37, 244, 161, 165, 244, 161, 239, 86, 161, 35, 171, 208, 191, 180, 202, 55, 60, 188, 55, 191, 2, 201, 62, 243, 200, 195, 10, 128, 4, 35, 32, 249, 127, 0, 9, 126, 109, 216, 82, 2, 145, 177, 2, 221, 122, 121, 252, 45, 22, 185, 63, 48, 98, 111, 95, 89, 246, 2, 142, 0, 218, 41, 216, 4, 0, 0]");

    let bytes_default = Program::serialize_program(&program);
    insta::assert_compact_debug_snapshot!(bytes_default, @"[31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 181, 144, 33, 14, 2, 65, 12, 69, 219, 206, 69, 144, 224, 32, 156, 128, 108, 72, 80, 4, 73, 72, 16, 36, 172, 219, 4, 50, 139, 65, 206, 13, 218, 14, 2, 185, 2, 197, 1, 8, 120, 46, 178, 14, 137, 193, 51, 16, 4, 138, 25, 196, 86, 255, 255, 243, 250, 140, 250, 125, 101, 188, 59, 100, 139, 162, 216, 161, 2, 10, 121, 230, 107, 11, 126, 31, 126, 55, 76, 90, 227, 56, 40, 203, 220, 110, 102, 185, 93, 121, 86, 141, 55, 40, 100, 186, 203, 177, 173, 123, 85, 231, 60, 25, 158, 156, 155, 206, 219, 253, 219, 104, 123, 89, 75, 86, 63, 252, 61, 132, 76, 116, 6, 4, 4, 153, 33, 252, 169, 255, 51, 64, 2, 3, 69, 103, 232, 163, 139, 148, 82, 117, 5, 177, 44, 230, 133, 141, 210, 12, 54, 198, 213, 189, 33, 128, 129, 159, 145, 215, 78, 168, 40, 2, 0, 0]");

    assert_deserialization(&program, [bytes_msgpack, bytes_default]);
}
