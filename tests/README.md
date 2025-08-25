# Tests Structure

Esta es la estructura de tests reorganizada para crypto-cli, siguiendo las mejores prácticas de Go.

## 📁 Estructura de Directorios

```
crypto-cli/
├── tests/                           # Directorio dedicado para todos los tests
│   ├── unit/                        # Tests unitarios
│   │   └── crypto_test.go           # Tests del paquete internal/crypto
│   ├── integration/                 # Tests de integración
│   │   └── cli_test.go              # Tests end-to-end del CLI
│   ├── testdata/                    # Datos de prueba compartidos
│   │   ├── small_file.txt           # Archivo pequeño de texto
│   │   ├── text_file.txt            # Archivo de texto mediano
│   │   ├── empty_file.txt           # Archivo vacío
│   │   └── medium_file.bin          # Archivo binario de 1KB
│   ├── run_tests.sh                 # Script para ejecutar tests
│   └── README.md                    # Este archivo
├── cmd/                             # Código de comandos (sin tests)
├── internal/                        # Código interno (sin tests)
└── main.go
```

## 🔧 Scripts de Test

### Script Principal: `run_tests.sh`

Un script bash conveniente para ejecutar diferentes tipos de tests:

```bash
# Ejecutar todos los tests
./tests/run_tests.sh all

# Solo tests unitarios
./tests/run_tests.sh unit

# Solo tests de integración
./tests/run_tests.sh integration

# Tests con cobertura
./tests/run_tests.sh coverage

# Benchmarks
./tests/run_tests.sh benchmarks

# Test específico
./tests/run_tests.sh specific TestEncryptDecryptFile

# Limpiar artifacts
./tests/run_tests.sh clean
```

## 📊 Tipos de Tests

### 1. Tests Unitarios (`tests/unit/`)

**Ubicación**: `tests/unit/crypto_test.go`

**Qué testean**:
- Funciones individuales del paquete `internal/crypto`
- Lógica de cifrado y descifrado
- Manejo de errores
- Casos edge (archivos vacíos, tamaños específicos)
- Performance (benchmarks)

**Características**:
- Rápidos de ejecutar
- No dependen de recursos externos
- Utilizan el patrón `crypto_test` (external test package)
- Incluyen benchmarks

### 2. Tests de Integración (`tests/integration/`)

**Ubicación**: `tests/integration/cli_test.go`

**Qué testean**:
- Comandos CLI completos (end-to-end)
- Flujo completo de cifrado → descifrado
- Manejo de errores en CLI
- Diferentes tamaños de clave
- Credenciales incorrectas

**Características**:
- Ejecutan el binario real
- Prueban la experiencia del usuario
- Más lentos pero más realistas
- Validan mensajes de salida

### 3. Datos de Prueba (`tests/testdata/`)

Archivos compartidos para tests consistentes:

- **`small_file.txt`**: "Hello, World!" (texto simple)
- **`text_file.txt`**: Lorem ipsum (texto largo)
- **`empty_file.txt`**: Archivo vacío
- **`medium_file.bin`**: Datos binarios aleatorios (1KB)

## 🚀 Ejecutar Tests

### Comandos Directos con Go

```bash
# Tests unitarios
go test ./tests/unit/... -v

# Tests de integración (requiere compilar primero)
go build -o crypto-cli ./main.go
go test ./tests/integration/... -v

# Todos los tests
go test ./tests/... -v

# Con cobertura
go test ./tests/unit/... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

# Benchmarks
go test ./tests/unit/... -bench=. -benchmem
```

### Con el Script de Conveniencia

```bash
# El script maneja la compilación automáticamente
./tests/run_tests.sh all
```

## 📈 Ventajas de esta Estructura

### ✅ **Organización Clara**
- **Separación**: Tests separados del código fuente
- **Categorización**: Unit vs Integration claramente divididos
- **Reutilización**: Datos de prueba compartidos

### ✅ **Mantenimiento**
- **Fácil de encontrar**: Tests organizados lógicamente
- **Fácil de extender**: Agregar nuevos tests en categorías apropiadas
- **Fácil de ejecutar**: Scripts convenientes

### ✅ **CI/CD Friendly**
- **Ejecución selectiva**: Puedes ejecutar solo unit tests para feedback rápido
- **Paralelización**: Unit e integration tests pueden ejecutarse en paralelo
- **Cobertura clara**: Reportes de cobertura centralizados

### ✅ **Escalabilidad**
- **Nuevas funcionalidades**: Fácil agregar tests para nuevos features
- **Performance**: Benchmarks organizados
- **Datos de prueba**: Centralizados y reutilizables

## 🔍 Cobertura de Tests

### Tests Unitarios Cubren:
- ✅ Ciclo completo encrypt/decrypt
- ✅ Diferentes tamaños de clave (128, 192, 256)
- ✅ Archivos vacíos y de diferentes tamaños
- ✅ Manejo de errores (credenciales incorrectas, archivos inválidos)
- ✅ Validación de padding PKCS#7
- ✅ Performance benchmarking

### Tests de Integración Cubren:
- ✅ CLI end-to-end workflows
- ✅ Validación de mensajes de salida
- ✅ Manejo de flags y argumentos
- ✅ Casos de error en CLI
- ✅ Múltiples tamaños de clave vía CLI

## 📋 Próximos Pasos

Para extender esta estructura:

1. **Agregar más tipos de test**:
   - `tests/performance/` para tests de carga
   - `tests/security/` para tests de seguridad específicos

2. **Más datos de prueba**:
   - Archivos grandes (MB+)
   - Archivos con caracteres especiales
   - Archivos binarios específicos

3. **Automatización**:
   - GitHub Actions workflows
   - Pre-commit hooks
   - Cobertura mínima requerida

Esta estructura proporciona una base sólida y escalable para el testing de crypto-cli. 🚀
