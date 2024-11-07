#pragma once
#include <vector>
#include <string>

#include <geek/global.h>

namespace geek {
struct DisAsmConfig {
	uint64_t runtime_address;
};

class DisAsmInstruction;
class DisAssembler {
public:
	enum class MachineMode : uint8_t {
		/**
		 * 64 λ��ģʽ��
		 *
		 * �����ִ� x86_64��AMD64/Intel64���ܹ��µ� 64 λģʽ��
		 *
		 * ֧�� 64 λ�����ַ�ռ�� 64 λ�Ĵ�����
		 */
		kLong64,
		/**
		 * 32 λ����ģʽ�������� 64 λ��ģʽ�µ� 32 λ����ģʽ��
		 *
		 * ���� 32 λ������ 64 λ����ϵͳ�����С�
		 *
		 * ����֧�־ɵ� 32 λӦ�ó����Լ��� x86_64 ϵͳ��
		 */
		kLongCompat32,
		/**
		 * 16 λ����ģʽ�������� 64 λ��ģʽ�µ� 16 λ����ģʽ��
		 *
		 * ���� 16 λ������ 64 λ������ִ�У�ͨ�����ڼ����ԡ�
		 */
		kLongCompat16,
		/**
		 * 32 λ����ģʽ��
		 *
		 * ֧�� 4 GB �������ַ�ռ�� 32 λ�Ĵ�����
		 */
		kLegacy32,
		/**
		 * 16 λ����ģʽ��
		 *
		 * ��ģʽ��֧�ֱ������ڴ���ʣ���ʹ�� 16 λ�Ĵ����Ͷ�Ѱַ����ַ�ռ��С��
		 */
		kLegacy16,
		/**
		 * 16 λʵģʽ��
		 *
		 * û���ڴ汣���������ַ�ռ䣬��֧�ֶ�+ƫ�Ƶ�Ѱַ��ʽ��ʵ��Ѱַ���������� 1 MB �ڴ�֮�ڡ�
		 */
		kReal16,
	};

	enum class StackWidth : uint8_t {
		/**
		 * 16 λջ��
		 *
		 * ͨ������ 16 λģʽ����ʵģʽ ZYDIS_MACHINE_MODE_REAL_16 �򱣻�ģʽ ZYDIS_MACHINE_MODE_LEGACY_16����
		 *
		 * ջָ�루SP��ʹ�� 16 λ�Ĵ�����ʾ��ջ�������� 16 λ��ȡ�
		 */
		k16,
		/**
		 * 32 λջ��
		 *
		 * ������ 32 λ����ģʽ���� ZYDIS_MACHINE_MODE_LEGACY_32����
		 *
		 * ջָ�루ESP��Ϊ 32 λ��ȣ�ջ�������� 32 λ��ȡ�
		 */
		k32,
		/**
		 * 64 λջ��
		 *
		 * ���� 64 λ��ģʽ���� ZYDIS_MACHINE_MODE_LONG_64����
		 *
		 * ջָ�루RSP��Ϊ 64 λ��ȣ�ջ�������� 64 λ��ȡ�
		 */
		k64
	};

	enum class FormatterStyle {
		/**
		 * AT&T ���Դ�� Unix ������
		 *
		 * ������˳���� Intel ����෴����Դ��Ŀ�꣨���� mov %ebx, %eax ��ʾ�� ebx ��ֵ���Ƶ� eax �У���
		 *
		 * ʹ�� % ǰ׺����ʶ�Ĵ������� %eax, %ebx����
		 *
		 * ͨ������ Linux ƽ̨�� GDB �ȹ��ߡ�
		 */
		kATT,
		/**
		 * Intel ���
		 *
		 * ������˳���Ŀ�굽Դ������ mov eax, ebx ��ʾ�� ebx ��ֵ���Ƶ� eax �У���
		 *
		 * ʹ��ͨ�õļĴ����������� eax, ebx����
		 *
		 * ������ Windows ƽ̨�� IDA��X86Dbg �ȹ����С�
		 */
		kIntel,
		/**
		 * Microsoft Macro Assembler (MASM) ���
		 *
		 * runtime-address �����ģʽ������.
		 */
		kIntelMasm,
	};

	DisAssembler(MachineMode machine_mode, StackWidth stack_width, FormatterStyle style = FormatterStyle::kIntel);
	~DisAssembler();

	const std::vector<uint8_t>& CodeBuffer() const;
	void SetCodeBuffer(const std::vector<uint8_t>& buf);
	void SetCodeBuffer(std::vector<uint8_t>&& buf);

	const DisAsmConfig& Config() const;
	DisAsmConfig& Config();

	std::vector<DisAsmInstruction> DecodeInstructions() const;

	_GEEK_IMPL
};

class DisAsmInstruction {
public:
	DisAsmInstruction(uint64_t runtime_address, std::string_view instruction);

	uint64_t runtime_address() const { return runtime_address_; }
	std::string_view instruction() const { return instruction_; }

	std::string SimpleFormat() const;

private:
	uint64_t runtime_address_;
	std::string instruction_;
};
}
