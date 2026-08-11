# Add public decode_predicado_from_bytes function
with open('crates/sak-core/src/gobernanza/corpus_durable.rs', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find the line with 'fn leer_str_u16'
insert_idx = None
for i, line in enumerate(lines):
    if line.strip().startswith('fn leer_str_u16(r:'):
        insert_idx = i
        break

if insert_idx is None:
    print('ERROR: could not find insert point')
    exit(1)

new_lines = [
    '\n',
    '/// Decodifica un `Predicado` desde bytes en formato canonico (para tests).\n',
    'pub fn decode_predicado_from_bytes(bytes: &[u8]) -> Result<Predicado, ErrorCorpusDurable> {\n',
    '    let mut r = Lector::new(bytes);\n',
    '    decode_predicado(&mut r)\n',
    '}\n',
    '\n',
]

lines = lines[:insert_idx] + new_lines + lines[insert_idx:]

with open('crates/sak-core/src/gobernanza/corpus_durable.rs', 'w', encoding='utf-8') as f:
    f.writelines(lines)

print('done')