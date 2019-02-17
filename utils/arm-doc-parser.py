#!/usr/bin/python
# Copyright (C) Jean-Baptiste Cayrou
# This program is published under a MIT license
# Script adapted from https://github.com/jbcayrou/arm-xml-doc-parser
# 
# Tool that extracts co processor registers from XML ARM documentation:
# https://developer.arm.com/-/media/developer/products/architecture/armv8-a-architecture/ARMv83A-SysReg-00bet4.tar.gz?la=en

import sys
import os
import xml.etree.ElementTree as ET
import copy
from collections import OrderedDict

DEBUG=0

UNICORN_PATH_BASE= None
ARM_CPREG_FNAME = "arm_cpreg.h"
ARM_CPREG_MACRO = "UC_ARM_CPREG_LIST"
ARM_CPREG_INFO_FNAME = "arm_cpreg_info.h"
ARM_CPREG_INFO_MACRO = "UC_ARM_CPREG_INFO_LIST"

ARM64_CPREG_FNAME = "arm64_cpreg.h"
ARM64_CPREG_MACRO = "UC_ARM64_CPREG_LIST"
ARM64_CPREG_INFO_FNAME = "arm64_cpreg_info.h"
ARM64_CPREG_INFO_MACRO = "UC_ARM64_CPREG_INFO_LIST"

# exclude UC_ARM64_REG_NZCV (MSR access only for ARMv8) access with cpsr_read
EXCLUDE_REGS = ["NZCV"]

def debug(str):
	if DEBUG:
		print str

# TODO : Should use classes like this ...
class cpreg_info:

	def __init__(self):
		self.reg_name = ""
		self.execution_state = 0
		self.inst_read_code = 0

		self.coproc = 0
		self.CRn = 0
		self.CRm = 0
		self.opc0 = 0
		self.opc1 = 0
		self.opc2 = 0


def parse_file(filename):

	print "Parsing file : %s ..." %filename
	obj_list = []
	obj = {}


	tree = ET.parse(filename)
	root = tree.getroot()

	root[0][0].attrib["execution_state"]


	execution_state = root.find("registers/register").attrib["execution_state"]
	reg_name = root.find("registers/register/reg_short_name").text
	instructions = root.find(".//*access_instructions")
 

	if instructions is None:
		return []

	access_instruction = root.find(".//*access_instruction").attrib["id"] # MRC, MRC2, MRRC, MRRC2 ,MRS, VMRS, MRS_br (banked)

 	if access_instruction in ["MRS_br", "VMRS"]:
 		return []

	varname = None

	for ins in instructions:
		if ins.tag == "defvar":
			tmp_varfields = {}
			obj = {}
			for vardef in ins:

				obj["execution_state"] = execution_state
				obj["access_instruction"] = access_instruction

				if ("asmname" in vardef.attrib and vardef.attrib["asmname"] == "systemreg" ):
					obj["reg_name"] = vardef.attrib["asmvalue"]
				else:
					obj["reg_name"] = reg_name
				
				for enc in vardef:
					key = enc.attrib["n"]

					if "varname" in enc.attrib:
						tmp_varfields[key] = {}

						varname = enc.attrib["varname"]
						tmp_varfields[key]["varname"] = enc.attrib["varname"]
						tmp_varfields[key]["tmp_val"] = 0
						if key in ["CRn", "CRm"]:
							msb = 3
						elif key == "op0":
							msb = 1
						else:
							msb = 2
						tmp_varfields[key]["msb"] = msb
						tmp_varfields[key]["lsb"] = 0

					elif "width" in enc.attrib:
						encbit_val = 0
						for encbit in enc:
							if "v" in encbit.attrib:
								msb = int(encbit.attrib["msb"])
								lsb = int(encbit.attrib["lsb"])
								val = int(encbit.attrib["v"],2)

								encbit_val = encbit_val | (val &(msb-lsb + 1))<<lsb
							else:
								for encvar in encbit:
									tmp_varfields[key] = {}

									msb = int(encvar.attrib["msb"])
									lsb = int(encvar.attrib["lsb"])

									tmp_varfields[key]["varname"] = encvar.attrib["name"]
									tmp_varfields[key]["tmp_val"] = encbit_val
									tmp_varfields[key]["msb"] = msb
									tmp_varfields[key]["lsb"] = lsb
					else:
						val = int(enc.attrib["v"], 2)
					obj[key] = val

				if "CRn" not in obj:
					obj["CRn"] = 0 # CRn does not exist for MRRC
				if "opc2" not in obj:
					obj["opc2"] = 0 # opc2 does not exist for MRRC

			# Need to generate all registers and replace REG_NAME<n> by 'n' values
			if len(tmp_varfields.keys())==0:
				obj_list.append(obj)
			else:
				tmp_gen_objs = [obj]

				for variable in root.find(".//*reg_variables"):
					variable_name_iter = variable.attrib["variable"]
					debug("Proccess variable '%s'" % variable_name_iter)
					vals = []
					new_tmp_gen_objs = []

					if "max" in variable.attrib:
						nb_min = 0
						nb_max = int(variable.attrib["max"])
						vals = range(nb_min, nb_max)
					else:
						for reg_variable_val in variable:
							vals.append(int(reg_variable_val.text))
					debug("\t Gen list is : %r" %vals)
					for gen in vals:

						for tmp_obj in tmp_gen_objs:
							tmp_new_obj = copy.deepcopy(tmp_obj)
							if "varname_gen" not in tmp_new_obj:
								tmp_new_obj["varname_gen"]= {}
							gen_id = gen

							tmp_new_obj["varname_gen"][variable_name_iter] = gen_id
							for key, v in tmp_varfields.items():
								varname = v["varname"]
								size_msk = v["msb"]-v["lsb"] + 1
								msk = int("1"*size_msk,2)
								gen_val = v["tmp_val"] | ( (gen&msk)<< v["lsb"] )

								if varname == variable_name_iter:
									debug("\t Generating %s=%d and val : %d" % (key, gen, gen_val))
									tmp_new_obj[key] = gen_val

							new_tmp_gen_objs.append(tmp_new_obj)

					tmp_gen_objs = list(new_tmp_gen_objs) # Copy the list

				# Update register name by remplacing <X> variables
				debug("Registers generated : %d " % len(tmp_gen_objs))
				for tmp_obj in tmp_gen_objs:

					for gen_name, gen_val  in tmp_obj["varname_gen"].items():
						tmp_obj["reg_name"] = tmp_obj["reg_name"].replace("<%s>"%gen_name, "%s"%gen_val)
				obj_list += tmp_gen_objs
	debug("****************************")
	debug(obj_list)
	debug("****************************")

	#Remove doublon, for instance in AArch32-icv_igrpen0.xml ICV_IGRPEN0 is defined twice
	ret_list = OrderedDict()
	for o in obj_list:
		if o["reg_name"] not in EXCLUDE_REGS:
			ret_list[o["reg_name"]] = o

	return ret_list



def gen_enum(objs, is_arm64):

	if is_arm64:
		prefix = "ARM64_"
	else:
		prefix = "ARM_"
	s = """
/* Autogen header for Unicorn Engine - DONOT MODIFY */
#ifndef UNICORN_%s_CPREG_H
#define UNICORN_%s_CPREG_H

""" % (prefix,prefix)

	prefix = "UC_"+prefix

	s += "#define %s \\\n"%(ARM64_CPREG_MACRO if is_arm64 else ARM_CPREG_MACRO)
	for obj in objs.values():
		if obj["execution_state"] == "AArch64":
			prefix = "UC_ARM64_"
		else:
			prefix = "UC_ARM_"

		
		reg_name = obj["reg_name"]

		
		tmp = "\t %sREG_%-16s, \\\n" % (prefix, reg_name)

		s += tmp

	s += "\n\n#endif"
	return s

def gen_cpreg_info(objs, is_arm64):
	
	if is_arm64:
		prefix = "ARM64_"
	else:
		prefix = "ARM_"
	s = """
/* Autogen header for Unicorn Engine - DONOT MODIFY */
#ifndef UNICORN_%s_CPREG_INFO_H
#define UNICORN_%s_CPREG_INFO_H

""" % (prefix,prefix)
	
	prefix = "UC_"+prefix

	s += "#define %s \\\n"%(ARM64_CPREG_INFO_MACRO if is_arm64 else ARM_CPREG_INFO_MACRO)
	for obj in objs.values():


		
		reg_name = obj["reg_name"]
		if is_arm64:
			tmp = "{ %sREG_%-16s, %4d, %4d, %4d, %4d, %4d, %4d },\\\n" % (prefix, reg_name, 0, obj["CRn"], obj["CRm"], obj["op0"], obj["op1"], obj["op2"])
		else:
			tmp = "{ %sREG_%-16s, %4d, %4d, %4d, %4d, %4d, %4d },\\\n" % (prefix, reg_name, obj["coproc"], obj["CRn"], obj["CRm"], 0, obj["opc1"], obj["opc2"])

		s += tmp

	s += "\n\n#endif"
	return s

def gen_entries(objs, is_arm64=False):
	print "###################################################"
	print "Generating Header C file for co-processor registers"
	print "###################################################"

	# Generate coprocessor enum 
	if is_arm64:
		file = UNICORN_PATH_BASE+"/include/unicorn/"+ARM64_CPREG_FNAME
	else:
		file = UNICORN_PATH_BASE+"/include/unicorn/"+ARM_CPREG_FNAME

	arm_cpreg_h_data = gen_enum(objs, is_arm64)
	f = open(file,"w")
	f.write(arm_cpreg_h_data)
	f.close()
	print("Writing %s file ..."% file)

	# Generate coprocessor info with cp, op, Rn, Rm ... matching
	if is_arm64:
		file = UNICORN_PATH_BASE+"/qemu/target-arm/"+ARM64_CPREG_INFO_FNAME
	else:
		file = UNICORN_PATH_BASE+"/qemu/target-arm/"+ARM_CPREG_INFO_FNAME

	arm_cpreg_info_h_data = gen_cpreg_info(objs, is_arm64)
	f = open(file,"w")
	f.write(arm_cpreg_info_h_data)
	f.close()
	print("Writing %s file ..."% file)


def parse_arm_regs(xml_doc_path, is_arm64):

	filename = "AArch64-regindex.xml" if (is_arm64) else "AArch32-regindex.xml"

	if not os.path.exists(arm_xml_path +"/" +filename):
		print "Path Incorect"
		return

	tree = ET.parse("%s/%s" % (xml_doc_path, filename))
	root = tree.getroot()	
	regs = root.findall(".//*register_link")

	files = OrderedDict()
	for r in regs:
		f = r.attrib["registerfile"]
		files[f] =1


	registers = OrderedDict()
	for f in files.keys():
		registers.update(parse_file(arm_xml_path + "/"+ f))

	print gen_entries(registers, is_arm64)

def aarch32_registers_files(xml_doc_path):
	parse_arm_regs(xml_doc_path, False)

def aarch64_registers_files(xml_doc_path):
	parse_arm_regs(xml_doc_path, True)


if __name__ == "__main__":

	if len(sys.argv) !=3:
		print "Usage : "
		print "%s <path_to_arm_xml_folder> <unicorn_base>"  % sys.argv[0]
		print "Where path point to 'SysReg_v83A_xml-00bet4/'"
		exit(1)

	arm_xml_path = sys.argv[1]
	if not os.path.exists(arm_xml_path):
		print "Path Incorect"
		exit(2)

	UNICORN_PATH_BASE = sys.argv[2]
	if not os.path.exists(UNICORN_PATH_BASE+"/"+"uc.c"):
		print "Unicorn base path incorrect"
		exit(2)

aarch32_registers_files(arm_xml_path)
aarch64_registers_files(arm_xml_path)