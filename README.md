# Method Anti Tamper

### A lightweight tamper detection system for .NET applications

**TamperCheck** is a tamper detection mechanism that verifies the integrity of your application's code by checking method opcodes at runtime. If tampering is detected, the system sets an environment variable that prevents the application from running, even if the modifications are reverted.

---

## Features

- **Easy Integration**: Simply drag and drop your `.exe` file to protect your application from tampering.
- **Environment-Based Protection**: Sets a tamper detection flag via environment variables to ensure persistent protection after tampering is detected.
- **Opcode Verification**: Validates the integrity of method opcodes to detect unauthorized modifications.
- **Designed for .NET Framework**: Built for .NET Framework applications, but can be adapted for .NET Core and .NET 5+ support.

---

## How it Works

1. **Opcode Verification**: At runtime, TamperCheck compares the opcodes of methods to a predefined hash. If there are any discrepancies, tampering is detected.
2. **Environment Variable**: Once tampering is detected, an environment variable `TAMPER_DETECTED` is set to `"DETECTED"`. On subsequent application runs, if this environment variable is present, the application will refuse to start, ensuring protection even after attempts to revert the modifications.
3. **Automatic Tamper Detection**: Protect your application in seconds with a simple drag-and-drop of your `.exe` file into the TamperCheck app.

---

## How to Use

### Step-by-Step Instructions

1. **Download MethodAntiTamper**: Get the latest release of **MethodAntiTamper** from the [releases page](#).
2. **Drag & Drop**: Drag and drop your `.exe` file into the tamper application.
   - The app will automatically inject the tamper protection code into your application.
3. **Run Your Application**: After injection, your application will be protected by **MethodAntiTamper**.
4. **Tamper Detection**: If any modifications are made to your application's code, tampering will be detected at runtime, and the application will stop functioning.

### Checking the Environment Variable

If tampering is detected, the environment variable `TAMPER_DETECTED` will be set. You can manually verify the value of the variable:

#### On Windows (Command Prompt):
```bash
echo %TAMPER_DETECTED%
