using System;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text;

namespace tamper
{
    public static class TamperCheck
    {
        public static OpCode[] multiByteOpCodes;
        public static OpCode[] singleByteOpCodes; 
        static TamperCheck() {

            // Check for prior tampering (environment variable check)
            if (Environment.GetEnvironmentVariable("TAMPER_DETECTED") == "DETECTED")
            {
                throw new Exception("Tampering was previously detected. The application cannot run.");
            }

            singleByteOpCodes = new OpCode[0x100];
            multiByteOpCodes = new OpCode[0x100];
            FieldInfo[] infoArray1 = typeof(OpCodes).GetFields();
            for (int num1 = 0; num1 < infoArray1.Length; num1++)
            {
                FieldInfo info1 = infoArray1[num1];
                if (info1.FieldType == typeof(OpCode))
                {
                    OpCode code1 = (OpCode)info1.GetValue(null);
                    ushort num2 = (ushort)code1.Value;
                    if (num2 < 0x100)
                    {
                        singleByteOpCodes[(int)num2] = code1;
                    }
                    else
                    {
                        if ((num2 & 0xff00) != 0xfe00)
                        {
                            throw new Exception("Invalid OpCode.");
                        }
                        multiByteOpCodes[num2 & 0xff] = code1;
                    }
                }
            }
        }
        public static void VerifyMethod(string expectedHash)
        {
            var method = new System.Diagnostics.StackTrace().GetFrame(1).GetMethod() as MethodInfo;
            if (method == null) throw new Exception("Could not retrieve method for tamper check!");

            MethodBody methodBody = method.GetMethodBody();
            if (methodBody == null) throw new Exception("A problem occurred loading the method contents. Please retry.");

            var ilBytes = methodBody.GetILAsByteArray();
            StringBuilder cilRepresentation = new StringBuilder();

            int position = 0;


            while (position < ilBytes.Length)
            {
                OpCode opCode;
                int codeValue = ilBytes[position++];

                if (codeValue != 0xfe)
                {
                    // Single-byte opcode
                    opCode = singleByteOpCodes[codeValue];
                }
                else
                {
                    // Multi-byte opcode
                    codeValue = ilBytes[position++];
                    opCode = multiByteOpCodes[codeValue];
                    codeValue = (ushort)(codeValue | 0xfe00);
                }

                cilRepresentation.Append(opCode.ToString());

                // Handle the operand
                if (opCode.OperandType != OperandType.InlineNone)
                {
                    switch (opCode.OperandType)
                    {
                        case OperandType.InlineBrTarget:
                            position += 4;
                            break;
                        case OperandType.ShortInlineBrTarget:
                            position += 1;
                            break;
                        case OperandType.InlineField:
                        case OperandType.InlineMethod:
                        case OperandType.InlineTok:
                        case OperandType.InlineType:
                            position += 4;
                            break;
                        case OperandType.InlineI:
                            position += 4;
                            break;
                        case OperandType.InlineI8:
                            position += 8;
                            break;
                        case OperandType.InlineR:
                            position += 8;
                            break;
                        case OperandType.ShortInlineI:
                            position += 1;
                            break;
                        case OperandType.ShortInlineR:
                            position += 4;
                            break;
                        case OperandType.InlineString:
                            position += 4;
                            break;
                        case OperandType.InlineSwitch:
                            int cases = BitConverter.ToInt32(ilBytes, position);
                            position += 4;
                            for (int i = 0; i < cases; i++)
                            {
                                position += 4;
                            }
                            break;
                        case OperandType.InlineVar:
                            position += 2;
                            break;
                        case OperandType.ShortInlineVar:
                            position += 1;
                            break;
                    }
                }
                
            }
            
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(cilRepresentation.ToString()));
                string actualHash = Convert.ToBase64String(hashBytes);

                if (actualHash != expectedHash)
                {
                    Environment.SetEnvironmentVariable("TAMPER_DETECTED", "DETECTED");
                    throw new Exception("Method tampered with!");
                }
            }
        }
    }
   
}
