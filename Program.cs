using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;

namespace VMPImportFixer
{
    internal class Program
    {
        static ModuleDefMD _module;
        static Assembly _assembly;
        static int _field = 0;
        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Usage: VMPImportFixer.exe module.exe ref_module.exe");
                Console.ReadKey();
                return;
            }
         
            _module = ModuleDefMD.Load(args[0]);
            _assembly = Assembly.LoadFrom(args[1]);

            FindDecryptMethod();
            RestoreDelegates();
            InlineMethodsAndRemoveUnusedTypes();

            // Optional
            _module.GlobalType.FindStaticConstructor().Body.Instructions.Clear();
            _module.GlobalType.FindStaticConstructor().Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
           
            string filePath = Path.GetDirectoryName(_module.Location);
            string fileName = Path.GetFileNameWithoutExtension(_module.Location);
            string newName = fileName + "-decrypted" + Path.GetExtension(_module.Location);

            var NativemoduleWriterOptions = new NativeModuleWriterOptions(_module, false);
            NativemoduleWriterOptions.MetadataOptions.Flags = MetadataFlags.PreserveAll;
            NativemoduleWriterOptions.MetadataLogger = DummyLogger.NoThrowInstance;
            _module.NativeWrite(Path.Combine(filePath, newName), NativemoduleWriterOptions);

            Console.WriteLine($"File saved in: {Path.Combine(filePath, newName)}");
        }

        private static void FindDecryptMethod()
        {
            _field = _module.GetTypes()
                .SelectMany(type => type.Methods)
                .Where(md => md.HasBody && md.ReturnType == md.Module.CorLibTypes.Boolean && md.Body.Instructions.Count >= 370)
                .SelectMany(md => md.DeclaringType.Fields)
                .Select(field => field.MDToken.ToInt32())
                .FirstOrDefault();
        }

        private static void RestoreDelegates()
        {
            FieldInfo field = _assembly.ManifestModule.ResolveField(_field);
            object[] mds = (object[])field.GetValue(null);
            Console.WriteLine(mds.Length);
            foreach (TypeDef type in _module.GetTypes())
            {
                foreach (MethodDef md in type.Methods)
                {
                    if (!md.HasBody)
                    {
                        continue;
                    }
                    for (int i = 0; i < md.Body.Instructions.Count; i++)
                    {
                        try
                        {
                            if (md.Body.Instructions[i].OpCode != OpCodes.Ldsfld || !md.Body.Instructions[i + 1].IsLdcI4() || md.Body.Instructions[i + 2].OpCode != OpCodes.Ldelem_Ref)
                            {
                                continue;
                            }
                           
                            Delegate currentDelegate = (Delegate)mds[md.Body.Instructions[i + 1].GetLdcI4Value()];
                            object m_owner = currentDelegate.Method.GetType().GetField("m_owner", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(currentDelegate.Method);
                         
                            if (m_owner != null)
                            {
                                object m_resolver = m_owner.GetType().GetField("m_resolver", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(m_owner);
                               
                                if (m_resolver == null)
                                {
                                    continue;
                                }
                             
                                object m_scope = m_resolver.GetType().GetField("m_scope", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(m_resolver);
                                List<object> m_tokens = (List<object>)m_scope.GetType().GetField("m_tokens", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(m_scope);
                            
                                if (m_tokens[m_tokens.Count - 1] is RuntimeMethodHandle)
                                {
                                    RuntimeMethodHandle calledmd = (RuntimeMethodHandle)m_tokens[m_tokens.Count - 1];
                                    dynamic calledmdMInfo = calledmd.GetType().GetField("m_value", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(calledmd);
                                 
                                    if (calledmdMInfo != null)
                                    {
                                        try
                                        {
                                            string fullName = calledmdMInfo.GetType().GetProperty("FullName", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(calledmdMInfo)
                                                .ToString();
                                            if (fullName.Contains(".ctor") && !fullName.Contains("System.Windows.Forms.Form..ctor"))
                                            {
                                                md.Body.Instructions[md.Body.Instructions.Count - 2] = Instruction.Create(OpCodes.Newobj, md.Module.Import(calledmdMInfo));
                                                md.Body.Instructions[0] = Instruction.Create(OpCodes.Nop);
                                                md.Body.Instructions[1] = Instruction.Create(OpCodes.Nop);
                                                md.Body.Instructions[2] = Instruction.Create(OpCodes.Nop);
                                                md.Body.UpdateInstructionOffsets();
                                            }
                                            else
                                            {
                                                md.Body.Instructions[md.Body.Instructions.Count - 2] = Instruction.Create(OpCodes.Call, md.Module.Import(calledmdMInfo));
                                                md.Body.Instructions[0] = Instruction.Create(OpCodes.Nop);
                                                md.Body.Instructions[1] = Instruction.Create(OpCodes.Nop);
                                                md.Body.Instructions[2] = Instruction.Create(OpCodes.Nop);
                                                md.Body.UpdateInstructionOffsets();
                                            }
                                        }
                                        catch (Exception e2)
                                        {
                                            Console.ForegroundColor = ConsoleColor.Red;
                                            Console.WriteLine("ERROR: " + e2.Message);
                                        }
                                    }
                                }
                             
                                else if (m_tokens[m_tokens.Count - 1] is RuntimeFieldHandle)
                                {
                                    RuntimeFieldHandle calledField = (RuntimeFieldHandle)m_tokens[m_tokens.Count - 1];
                                    dynamic calledFieldFInfo = calledField.GetType().GetField("m_ptr", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(calledField);
                              
                                    if (calledFieldFInfo != null)
                                    {
                                        md.Body.Instructions[md.Body.Instructions.Count - 2] = Instruction.Create(OpCodes.Ldsfld, md.Module.Import(calledFieldFInfo));
                                        md.Body.Instructions[0] = Instruction.Create(OpCodes.Nop);
                                        md.Body.Instructions[1] = Instruction.Create(OpCodes.Nop);
                                        md.Body.Instructions[2] = Instruction.Create(OpCodes.Nop);
                                        md.Body.UpdateInstructionOffsets();
                                    }
                                }
                               
                                else
                                {
                                    Console.ForegroundColor = ConsoleColor.Cyan;
                                    Console.WriteLine("UNKNOWN");
                                    Console.ForegroundColor = ConsoleColor.Blue;
                                }
                                continue;
                            }
                            md.Body.Instructions[0] = Instruction.Create(OpCodes.Nop);
                            md.Body.Instructions[1] = Instruction.Create(OpCodes.Nop);
                            md.Body.Instructions[2] = Instruction.Create(OpCodes.Nop);
                            md.Body.Instructions[md.Body.Instructions.Count - 2] = Instruction.Create(OpCodes.Call, md.Module.Import(currentDelegate.Method));
                            md.Body.UpdateInstructionOffsets();
                        }
                        catch (Exception e)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("ERROR: " + e.Message);
                        }
                    }
                }
            }
        }

        private static void InlineMethodsAndRemoveUnusedTypes()
        {
            _module.GetTypes()
      .Where(type => type.BaseType?.FullName == "System.MulticastDelegate" && type.Methods.Count == 2)
      .ToList()
      .ForEach(type => _module.Types.Remove(type));

            _module.GetTypes()
               .SelectMany(type => type.Methods)
               .Where(method => method.HasBody)
               .SelectMany(method => method.Body.Instructions)
               .Where(instruction => instruction.OpCode == OpCodes.Call &&
                                      instruction.Operand is MethodDef operandCall &&
                                      operandCall.HasBody &&
                                      operandCall.Body.Instructions.Count >= 3 &&
                                      operandCall.Body.Instructions.Take(3).All(i => i.OpCode == OpCodes.Nop))
               .ToList()
               .ForEach(instruction =>
               {
                   var operandCall = (MethodDef)instruction.Operand;
                   var methodCall = operandCall.Body.Instructions[operandCall.Body.Instructions.Count - 2];
                   instruction.OpCode = methodCall.OpCode;
                   instruction.Operand = methodCall.Operand;
                   _module.Types.Remove(operandCall.DeclaringType);
               });

        }  
    }  
}
