import unicorn

try:
    unicorn.UC_HOOK_MEM_UNMAPPED
except AttributeError:
    assert(False and "Definition for UC_HOOK_MEM_UNMAPPED not generated")
