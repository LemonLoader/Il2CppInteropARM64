using Disarm;

namespace Il2CppInterop.Common.XrefScans;

public static class XrefScannerLowLevel
{
    public static IEnumerable<IntPtr> JumpTargets(IntPtr codeStart, bool ignoreRetn = false)
    {
        return JumpTargetsImpl(XrefScanner.DecoderForAddress(codeStart), ignoreRetn);
    }

    private static IEnumerable<IntPtr> JumpTargetsImpl(IEnumerable<Arm64Instruction> myDecoder, bool ignoreRetn)
    {
        var firstFlowControl = true;

        foreach (Arm64Instruction instruction in myDecoder)
        {
            if (instruction.MnemonicCategory.HasFlag(Arm64MnemonicCategory.Return) && !ignoreRetn)
                yield break;

            if (instruction is
                {
                    // Check if jump or call instruction
                    Mnemonic: Arm64Mnemonic.B or Arm64Mnemonic.BC or Arm64Mnemonic.BR or Arm64Mnemonic.BL or Arm64Mnemonic.BLR,
                    MnemonicConditionCode: Arm64ConditionCode.NONE,
                    FinalOpConditionCode: Arm64ConditionCode.NONE
                })
            {
                yield return (IntPtr)ExtractTargetAddress(in instruction);
                if (firstFlowControl && instruction.MnemonicCategory.HasFlag(Arm64MnemonicCategory.Branch)) yield break;

                firstFlowControl = false;
            }
        }
    }

    public static IEnumerable<IntPtr> CallAndIndirectTargets(IntPtr pointer)
    {
        return CallAndIndirectTargetsImpl(XrefScanner.DecoderForAddress(pointer, 1024 * 1024));
    }

    private static IEnumerable<IntPtr> CallAndIndirectTargetsImpl(IEnumerable<Arm64Instruction> decoder)
    {
        foreach (Arm64Instruction instruction in decoder)
        {
            if (instruction.MnemonicCategory.HasFlag(Arm64MnemonicCategory.Return))
                yield break;

            if (instruction.MnemonicCategory.HasFlag(Arm64MnemonicCategory.Branch) || instruction.MnemonicCategory.HasFlag(Arm64MnemonicCategory.ConditionalBranch))
            {
                var targetAddress = XrefScanner.ExtractTargetAddress(instruction);
                if (targetAddress != 0)
                    yield return (IntPtr)targetAddress;
                continue;
            }

            if ((instruction.Mnemonic == Arm64Mnemonic.ADR ||
                instruction.Mnemonic == Arm64Mnemonic.ADRP) &&
                instruction.Op0Kind == Arm64OperandKind.Register &&
                instruction.Op1Kind == Arm64OperandKind.ImmediatePcRelative)
            {
                var targetAddress = (IntPtr)instruction.Op1PcRelImm;
                if (targetAddress != IntPtr.Zero)
                    yield return targetAddress;
            }
        }
    }

    private static ulong ExtractTargetAddress(in Arm64Instruction instruction)
    {
        return instruction.Op0Kind switch
        {
            Arm64OperandKind.Immediate => (ulong)instruction.Op0Imm,
            Arm64OperandKind.ImmediatePcRelative => instruction.Address + (ulong)instruction.Op0Imm,
            _ => 0,
        };
    }
}
