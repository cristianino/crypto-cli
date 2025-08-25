# Testing Guide for crypto-cli

Esta guía describe cómo ejecutar y trabajar con los tests en crypto-cli.

## 🗂️ Nueva Estructura de Tests

Los tests han sido reorganizados en una estructura dedicada y profesional:

```
crypto-cli/
├── tests/                           # Directorio dedicado para todos los tests
│   ├── unit/                        # Tests unitarios
│   │   └── crypto_test.go           # Tests del paquete internal/crypto  
│   ├── integration/                 # Tests de integración
│   │   └── cli_test.go              # Tests end-to-end del CLI
│   ├── testdata/                    # Datos de prueba compartidos
│   │   ├── small_file.txt           # Archivos de prueba reutilizables
│   │   ├── text_file.txt
│   │   ├── empty_file.txt
│   │   └── medium_file.bin
│   ├── run_tests.sh                 # Script para ejecutar tests
│   └── README.md                    # Documentación detallada
```

## 🚀 Ejecutar Tests

### Script de Conveniencia (Recomendado)

```bash
# Ejecutar todos los tests
./tests/run_tests.sh all

# Solo tests unitarios (rápido)  
./tests/run_tests.sh unit

# Solo tests de integración
./tests/run_tests.sh integration

# Tests con cobertura
./tests/run_tests.sh coverage

# Benchmarks de rendimiento
./tests/run_tests.sh benchmarks

# Test específico
./tests/run_tests.sh specific TestEncryptDecryptFile

# Limpiar artifacts
./tests/run_tests.sh clean
```

### Comandos Directos con Go

```bash
# Tests unitarios
go test ./tests/unit/... -v

# Tests de integración
go test ./tests/integration/... -v

# Todos los tests
go test ./tests/... -v

# Con cobertura
go test ./tests/unit/... -coverpkg=./internal/... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

# Benchmarks
go test ./tests/unit/... -bench=. -benchmem
```

## Casos de Test Cubiertos

### Cifrado/Descifrado
- ✅ Cifrado y descifrado exitoso con diferentes tamaños de clave
- ✅ Archivos vacíos
- ✅ Archivos de diferentes tamaños (1 byte, 15 bytes, 16 bytes, 17 bytes, 1KB, 1KB+16 bytes)
- ✅ Validación de que los datos cifrados son diferentes de los originales
- ✅ Validación de que el descifrado restaura los datos originales

### Manejo de Errores
- ✅ Tamaños de clave inválidos (no 128, 192, o 256 bits)
- ✅ Archivos de entrada no existentes
- ✅ Rutas de salida inválidas
- ✅ Contraseñas incorrectas
- ✅ Sales incorrectas
- ✅ Tamaños de clave incorrectos para descifrado
- ✅ Archivos cifrados demasiado cortos
- ✅ Padding inválido

### Casos Especiales
- ✅ Archivos que requieren padding (no múltiplos del tamaño de bloque)
- ✅ Archivos exactamente del tamaño de bloque
- ✅ Verificación de IV aleatorio (cada cifrado es diferente)

## Rendimiento

Los benchmarks actuales muestran:

- **Cifrado**: ~51ms por archivo de 1KB
- **Descifrado**: ~50ms por archivo de 1KB
- **Uso de memoria**: ~33MB por operación

## Cobertura

La cobertura actual es del **54.6%** de las líneas de código en el paquete `internal/crypto`.

### Áreas cubiertas:
- ✅ Flujos principales de cifrado y descifrado
- ✅ Manejo de errores principales
- ✅ Validaciones de entrada
- ✅ Padding PKCS#7

### Mejoras potenciales:
- Agregar tests para casos edge adicionales
- Mejorar cobertura de manejo de errores de E/O
- Tests de concurrencia (múltiples operaciones simultáneas)

## Ejecución en CI/CD

Para integración continua, usar:

```bash
# Test completo con cobertura
go test ./... -race -coverprofile=coverage.out

# Verificar que la cobertura no baje del 50%
go tool cover -func=coverage.out | grep "total:" | awk '{print $3}' | sed 's/%//' | awk '{if ($1 < 50) exit 1}'
```
