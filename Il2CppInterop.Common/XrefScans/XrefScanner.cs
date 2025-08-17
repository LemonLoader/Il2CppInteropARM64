using System.Reflection;
using Disarm;
using Il2CppInterop.Common.Attributes;
using Microsoft.Extensions.Logging;

namespace Il2CppInterop.Common.XrefScans;

public static class XrefScanner
{
    public static unsafe IEnumerable<XrefInstance> XrefScan(MethodBase methodBase)
    {
        var fieldValue = Il2CppInteropUtils.GetIl2CppMethodInfoPointerFieldForGeneratedMethod(methodBase)
            ?.GetValue(null);
        if (fieldValue == null) return Enumerable.Empty<XrefInstance>();

        CachedScanResultsAttribute? cachedAttribute = null;
        try
        {
            cachedAttribute = methodBase.GetCustomAttribute<CachedScanResultsAttribute>(false);
        }
        catch (Exception e)
        {
            Logger.Instance.LogWarning("Failed to get custom attribute for {TypeName}.{MethodName}: {Error}. Falling back to scanning", methodBase.DeclaringType!.FullName, methodBase.Name, e.Message);
        }

        if (cachedAttribute == null)
        {
            XrefScanUtil.CallMetadataInitForMethod(methodBase);

            return XrefScanImpl(DecoderForAddress(*(IntPtr*)(IntPtr)fieldValue));
        }

        if (cachedAttribute.XrefRangeStart == cachedAttribute.XrefRangeEnd)
            return Enumerable.Empty<XrefInstance>();

        XrefScanMethodDb.CallMetadataInitForMethod(cachedAttribute);

        return XrefScanMethodDb.CachedXrefScan(cachedAttribute).Where(it =>
            it.Type == XrefType.Method || XrefScannerManager.Impl.XrefGlobalClassFilter(it.Pointer));
    }

    public static IEnumerable<XrefInstance> UsedBy(MethodBase methodBase)
    {
        var cachedAttribute = methodBase.GetCustomAttribute<CachedScanResultsAttribute>(false);
        if (cachedAttribute == null || cachedAttribute.RefRangeStart == cachedAttribute.RefRangeEnd)
            return Enumerable.Empty<XrefInstance>();

        return XrefScanMethodDb.ListUsers(cachedAttribute);
    }

    internal static unsafe IEnumerable<Arm64Instruction> DecoderForAddress(IntPtr codeStart, int lengthLimit = 1000)
    {
        if (codeStart == IntPtr.Zero) throw new NullReferenceException(nameof(codeStart));
        return Disassembler.Disassemble((byte*)codeStart, lengthLimit, (ulong)codeStart, Disassembler.Options.IgnoreErrors);
    }

    internal static IEnumerable<XrefInstance> XrefScanImpl(IEnumerable<Arm64Instruction> decoder, bool skipClassCheck = false)
    {
        foreach (Arm64Instruction instruction in decoder)
        {
            if (instruction.MnemonicCategory.HasFlag(Arm64MnemonicCategory.Return))
                yield break;

            if (instruction.Mnemonic == Arm64Mnemonic.BL || instruction.Mnemonic == Arm64Mnemonic.B)
            {
                var targetAddress = ExtractTargetAddress(instruction);
                if (targetAddress != 0)
                    yield return new XrefInstance(XrefType.Method, (nint)targetAddress, (nint)instruction.Address);
                continue;
            }

            if (instruction.MnemonicCategory.HasFlag(Arm64MnemonicCategory.Move))
            {
                XrefInstance? result = null;
                try
                {
                    if (instruction.Op1Kind == Arm64OperandKind.ImmediatePcRelative)
                    {
                        var movTarget = (IntPtr)((long)instruction.Address + instruction.Op1Imm);
                        if (skipClassCheck || XrefScannerManager.Impl.XrefGlobalClassFilter(movTarget))
                            result = new XrefInstance(XrefType.Global, movTarget, (IntPtr)instruction.Address);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Instance.LogError("{Error}", ex.ToString());
                }

                if (result != null)
                    yield return result.Value;
            }
        }
    }

    internal static ulong ExtractTargetAddress(in Arm64Instruction instruction)
    {
        return instruction.Op0Kind switch
        {
            Arm64OperandKind.Immediate => (ulong)instruction.Op0Imm,
            Arm64OperandKind.ImmediatePcRelative => instruction.Address + (ulong)instruction.Op0Imm,
            _ => 0,
        };
    }
}
