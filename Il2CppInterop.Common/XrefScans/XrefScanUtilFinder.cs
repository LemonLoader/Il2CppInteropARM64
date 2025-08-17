using Disarm;
using Disarm.InternalDisassembly;
using Iced.Intel;

namespace Il2CppInterop.Common.XrefScans;

internal static class XrefScanUtilFinder
{
    public static IntPtr FindLastRcxReadAddressBeforeCallTo(IntPtr codeStart, IntPtr callTarget)
    {
        var decoder = XrefScanner.DecoderForAddress(codeStart);
        var lastX0Read = IntPtr.Zero;

        foreach (Arm64Instruction instruction in decoder)
        {
            if (instruction.MnemonicCategory.HasFlag(Arm64MnemonicCategory.Return))
                return IntPtr.Zero;

            if (instruction.Mnemonic == Arm64Mnemonic.B)
                continue;

            if (instruction.Mnemonic == Arm64Mnemonic.BL || instruction.Mnemonic == Arm64Mnemonic.BLR)
            {
                var target = ExtractTargetAddress(instruction);
                if ((IntPtr)target == callTarget)
                    return lastX0Read;
            }

            if (instruction.Mnemonic == Arm64Mnemonic.LDR &&
                instruction.Op0Kind == Arm64OperandKind.Register &&
                instruction.Op0Reg == Arm64Register.X0 &&
                instruction.Op1Kind == Arm64OperandKind.ImmediatePcRelative)
            {
                var ldrTarget = (IntPtr)(instruction.Address + (ulong)instruction.MemOffset);

                lastX0Read = ldrTarget;
            }

            if ((instruction.Mnemonic == Arm64Mnemonic.ADR || instruction.Mnemonic == Arm64Mnemonic.ADRP) &&
                instruction.Op0Kind == Arm64OperandKind.Register &&
                instruction.Op0Reg == Arm64Register.X0 &&
                instruction.Op1Kind == Arm64OperandKind.ImmediatePcRelative)
            {
                lastX0Read = (IntPtr)(instruction.Op1PcRelImm);
            }
        }

        return IntPtr.Zero;
    }

    public static IntPtr FindByteWriteTargetRightAfterCallTo(IntPtr codeStart, IntPtr callTarget)
    {
        var decoder = XrefScanner.DecoderForAddress(codeStart);
        var seenCall = false;

        foreach (Arm64Instruction instruction in decoder)
        {
            if (instruction.MnemonicCategory.HasFlag(Arm64MnemonicCategory.Return))
                return IntPtr.Zero;

            if (instruction.Mnemonic == Arm64Mnemonic.B)
                continue;

            if (instruction.Mnemonic == Arm64Mnemonic.BL || instruction.Mnemonic == Arm64Mnemonic.BLR)
            {
                var target = ExtractTargetAddress(instruction);
                if ((IntPtr)target == callTarget)
                    seenCall = true;
            }

            if (instruction.MnemonicCategory.HasFlag(Arm64MnemonicCategory.Move) && seenCall)
            {
                if (instruction.Op0Kind == Arm64OperandKind.ImmediatePcRelative)
                    return (IntPtr)instruction.Op0PcRelImm;
            }
        }

        return IntPtr.Zero;
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
