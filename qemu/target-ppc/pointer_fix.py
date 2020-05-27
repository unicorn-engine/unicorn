#!/usr/bin/env python3
# Usage: patch_by_list.py <patch_list> <new_word> <offset> <src> <dst>
import os
import sys
import os.path

# class[0] -> not related to translate.c
# class[1] -> multiple primary lines
# class[2] -> other
err_class = [0, 0, 0]

filename = "translate_init.c"

# Get line number from a error/warning/note string
def get_lineno(s):
	s = s.split(":")
	if len(s) < 5:
		return None
	if s[3] != " warning" and s[3] != " error" and s[3] != " note":
		return None
	if not s[1].isdigit() or not s[2].isdigit():
		return None
	return int(s[1])

# Get error text from an error/warning/note string
def get_error(s):
	s = s.split(":")
	if len(s) < 5:
		return None
	if s[3] != " warning" and s[3] != " error" and s[3] != " note":
		return None
	if not s[1].isdigit() or not s[2].isdigit():
		return None
	return s[4]

# Get error type from an error/warning/note string
def get_type(s):
	s = s.split(":")
	if len(s) < 5:
		return None
	if s[3] != " warning" and s[3] != " error" and s[3] != " note":
		return None
	if not s[1].isdigit() or not s[2].isdigit():
		return None
	return s[3].strip()

# Process an error. Return a tuple of (lineno, [error message], [warning message], [extra messages]) or None
def proc_error(err):
	global err_class

	if len(err) == 0:
		return None

	primary = []					# err[0] contains the reason, primary contains translate.c lines, secondary contains other valuable lines
	secondary = []
	for l in err:
		if l.startswith(" ") or get_lineno(l) is None:
			continue
		elif filename + ":" in l:
			if ": At top level:" not in l and get_lineno(l) != None:
				primary.append(l)
		elif ": error:" in l or ": note: expected ‘" in l:
			secondary.append(l)

	if len(primary) == 0:								# Ignoring if not containing translate.c
		err_class[0] += 1
		return None

	if len(primary) > 1:								# If multiple primary and err[0] in primary then move the rest of primary to secondary
		primary_has_reason = False
		s = []
		for l in primary:
			if err[0] == l:
				primary_has_reason = True
			else:
				s.append(l)
		if primary_has_reason:
			primary = [err[0]]
			secondary.append(s)

	if len(primary) > 1:								# If multiple primary and err[0] in primary then select the lower line no
		lineno = None
		lineno_l = ""
		for l in primary:
			if not lineno or lineno > get_lineno(l):
				lineno = get_lineno(l)
				lineno_l = l
		primary.remove(lineno_l)
		secondary = secondary + primary
		primary = [lineno_l]
	primary = primary[0]

	if get_type(err[0]) == "error":
		return (get_lineno(primary), set([get_error(err[0])]), set(), secondary)
	else:
		return (get_lineno(primary), set(), set([get_error(err[0])]), secondary)

if __name__ == "__main__":
	with open(sys.argv[1], "rt") as f:
		errlog = f.readlines()

	err_list = {}
	prev_error = []
	for i in range(0, len(errlog)):
		l = errlog[i].strip("\n")
		if (": warning:" in l) or (": error:" in l):
			if len(prev_error) > 1:
				rc = proc_error(prev_error)
				if rc:
					if rc[0] in err_list:
						err_list[rc[0]] = (err_list[rc[0]][0] | rc[1], err_list[rc[0]][1] | rc[2], err_list[rc[0]][2] + rc[3])
					else:
						err_list[rc[0]] = (rc[1], rc[2], rc[3])
			prev_error = [l]
		elif l.strip() != "" and not l.startswith("In file included from ") and ": In function ‘" not in l:
			prev_error.append(l)


	with open(filename, "rt") as f:
		source = f.readlines()

	disascontext = 0
	passing_other = 0

	for err in err_list:
		if  " passing argument" in list(err_list[err][1])[0]:
			found = False
			for e in err_list[err][2]:
				for ee in e:
					if " note: expected ‘DisasContext * " in ee:
						found = True
#			print(err, " | ", err_list[err])
			if found:
				s_line = source[err-1]
				if "(ctx->uc->tcg_ctx" in s_line:
					print("Expected DisasContext *at", err)
					new_line = s_line.replace("(ctx->uc->tcg_ctx", "(ctx", 1)
					print(s_line)
					print(new_line)
					source[err-1] = new_line
					disascontext += 1
			else:
				passing_other += 1



	print(disascontext, passing_other)

#	for l in source:
#		print(l.strip("\n"))



