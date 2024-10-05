using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace tamper
{
    internal class Program
    {
        static MethodDef runtime_method;
        static void Main(string[] args)
        {
            ProcessAssembly(args[0]);
            Console.WriteLine("done");
            Console.ReadLine();

        }
        public static void InjectHashCheck(ModuleDefMD module, MethodDef method)
        {
            var ilProcessor = method.Body.Instructions;

            var ldstrInstruction = Instruction.Create(OpCodes.Ldstr, "PLACEHOLDER_HASH");
            var callInstruction = Instruction.Create(OpCodes.Call, runtime_method);

            ilProcessor.Insert(0, ldstrInstruction);
            ilProcessor.Insert(1, callInstruction);
        }

        public static string ComputeHash(MethodDef method)
        {
            var instructions = method.Body.Instructions;
            StringBuilder cilCode = new StringBuilder();

            foreach (var instr in instructions)
            {
                cilCode.Append(instr.OpCode.ToString());

            }

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(cilCode.ToString()));
                return Convert.ToBase64String(hashBytes);
            }
        }

        public static void InsertHashInMethod(ModuleDefMD module, MethodDef method)
        {
            InjectHashCheck(module, method);
            string computedHash = ComputeHash(method);
              
            foreach (var instr in method.Body.Instructions)
            {
                if (instr.OpCode == OpCodes.Ldstr && instr.Operand.Equals("PLACEHOLDER_HASH"))
                {
                    instr.Operand = computedHash;
                    break;
                }
            }
        }

        public static void ProcessAssembly(string assemblyPath)
        {
            ModuleDefMD module = ModuleDefMD.Load(assemblyPath);

            ModuleDefMD sourceModule = ModuleDefMD.Load(typeof(TamperCheck).Module);

            // Inject the TamperCheck class from sourceModule into targetModule
            var tamperCheckType = sourceModule.Types.FirstOrDefault(t => t.Name == "TamperCheck");
         
            if (tamperCheckType != null)
            {
                var members = InjectHelper.Inject(tamperCheckType, module.GlobalType, module);
                runtime_method = (MethodDef)members.Single(method => method.Name == "VerifyMethod");
            }
             
            foreach (var type in module.GetTypes().Where(x=>!x.IsGlobalModuleType))
            {
                foreach (var method in type.Methods.Where(m => m.HasBody))
                {
                    InsertHashInMethod(module, method);
                }
            }
             
            module.Write(Path.GetFileNameWithoutExtension(assemblyPath)+"-prot.exe");
        }
    }
}
