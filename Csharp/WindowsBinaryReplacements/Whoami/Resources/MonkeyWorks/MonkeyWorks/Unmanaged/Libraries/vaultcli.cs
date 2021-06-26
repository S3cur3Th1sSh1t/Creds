using System;
using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Libraries
{
    sealed class vaultcli
    {
        [DllImport("vaultcli.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern Boolean VaultEnumerateItems(
            IntPtr hVault,
            Int32 unknown,
            out Int32 dwItems,
            out IntPtr ppVaultGuids
        );

        [DllImport("vaultcli.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern Boolean VaultEnumerateVaults(
            Int32 unknown,
            out Int32 dwVaults,
            out IntPtr ppVaultGuids
        );

        [DllImport("vaultcli.dll", SetLastError = true, CharSet = CharSet.Auto, EntryPoint = "VaultGetItem")]
        public static extern Boolean VaultGetItem7(
            IntPtr hVault,
            ref Guid guid,
            IntPtr SchemaId,
            IntPtr Resource,
            IntPtr Identity,
            //IntPtr unknownPtr,
            Int32 unknown,
            out IntPtr hitem
        );

        [DllImport("vaultcli.dll", SetLastError = true, CharSet = CharSet.Auto, EntryPoint = "VaultGetItem")]
        public static extern Boolean VaultGetItem8(
            IntPtr hVault,
            ref Guid guid,
            IntPtr SchemaId,
            IntPtr Resource, 
            IntPtr Identity,
            IntPtr PackageSid,
            //IntPtr unknownPtr,
            Int32 unknown,
            out IntPtr hitem
        );

        [DllImport("vaultcli.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern Boolean VaultOpenVault(
            ref Guid guid,
            Int32 dwVaults,
            out IntPtr hItems
        );
    }
}