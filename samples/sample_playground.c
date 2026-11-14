/**
 * @file
 * @author Christoph Hindermann (bitmaskmixer)
 *
 * @brief
 * Sample application to analyse emulation with unicorn,
 * or to play around. Useful for testing, debugging, or to
 * reproduce bugs within a simple and minimal, but extendable framework.
 * The main reason for this file is to be able to native debug with gdb.
 *
 * This file uses a monolithic approach: Stick everything in one file.
 * That might make the code more complex than it is, but it fit's
 * better in the scheme of sample folder of unicorn.
 *
 * Feel free to jump to the main() method to see how it works :P
 *
 * Default hooks provides a little bit insight during a memory access,
 * and a fatal (invalid) error return codes will abort the application.
 *
 * The application should be changed to meet the needs, and providing
 * a filename as an argument during startup will load the binary file
 * and write it into the memory.
 *
 * The get_config() method defines default values for unicorn and
 * defines memory. Change them to your needs.
 *
 * @copyright Copyright (c) 2024 Christoph Hindermann.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <unicorn/unicorn.h>

/** Helper macro to check if compiled for Windows */
#define IS_WINDOWS \
    (defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64))

/** Defines the path separator. */
#if IS_WINDOWS
#define PATH_SEPARATOR_STR "\\"
#define PATH_SEPARATOR_CHAR '\\'
#else
#define PATH_SEPARATOR_STR "/"
#define PATH_SEPARATOR_CHAR '/'
#endif /* IS_WINDOWS */

/** Helper macro to declare unused variables to make the compiler happy. */
#define UNUSED(x) (void)x

/** Macro to get the filename only. */
#define FILENAME (strrchr(PATH_SEPARATOR_STR __FILE__, PATH_SEPARATOR_CHAR) + 1)

/** Formatter string to process a 64bit value to hex. */
#define HEX_ADDR_64 "0x%" PRIx64

/** Formatter string to process a 32bit value to hex. */
#define HEX_ADDR_32 "0x%" PRIx32

/**
 * @brief
 * Logs a formatted string.
 * @param fmt The format string, printf like.
 * @param args Optional arguments to the format string.
 */
#define LOG_INFO(fmt, ...) \
    printf("[%s:%u] " fmt, FILENAME, __LINE__, ##__VA_ARGS__)

/**
 * @brief
 * Ensures @p predicate is true and exits with @p return_code on failue.
 * @param predicate The predicate to be checked.
 * @param return_code The exit return code.
 * @param fmt The format string, printf like.
 * @param args Optional arguments to the format string.
 */
#define ENSURE(predicate, return_code, fmt, ...)        \
    if (!(predicate))                                   \
    {                                                   \
        LOG_INFO("Ensure failed. " fmt, ##__VA_ARGS__); \
        exit(return_code);                              \
    }                                                   \
    UNUSED(return_code)  // to be able to insert a ;

/**
 * @brief
 * Ensures @p error_code contains no error.
 * If the error is set, log it and exit the process.
 * @param error_code The error_code to be checked.
 * @param fmt The format string, printf like.
 * @param args Optional arguments to the format string.
 */
#define ENSURE_UC(error_code, fmt, ...)                                   \
    if (error_code != UC_ERR_OK)                                          \
    {                                                                     \
        const char* uc_error_str = uc_strerror(error_code);               \
        ENSURE(error_code == UC_ERR_OK, (int32_t)error_code,              \
               "Error: %d - %s\n" fmt, (int32_t)error_code, uc_error_str, \
               ##__VA_ARGS__);                                            \
    }                                                                     \
    UNUSED(error_code)  // to be able to insert a ;

/**
 * @brief
 * Struct to store details about memory.
 */
struct Memory
{
    uint64_t address;    //!< Base address.
    size_t size;         //!< Size of the memory.
    int32_t permission;  //!< Bit mask of uc_prot permissions.
    const char* name;    //!< Name of the memory.
};

/**
 * @brief
 * Struct to store memory details as array member.
 */
struct Memory_config
{
    size_t count;             //!< Number of elements.
    struct Memory memory[8];  //!< Details about the memory.
    struct Memory* base;      //!< Base memory to start the cpu emulation.
};

/**
 * @brief
 * Struct to store details about unicorn and the environment.
 */
struct Playground_config
{
    uc_engine* uc;                       //!< Unicorn instance.
    uc_arch cpu_architecture;            //!< CPU architecture.
    uc_mode cpu_mode;                    //!< CPU mode.
    struct Memory_config memory_config;  //!< Memory configuration.
    uint64_t pc;                         //!< Programm counter value.
    uint64_t sp;                         //!< Stack pointer value.
    int32_t pc_reg;                      //!< Programm counter register.
    int32_t sp_reg;                      //!< Stack pointer register.
    char* code_to_execute;               //!< Pointer to the code to execute.
    size_t code_size;           //!< Number of bytes of the code to execute.
    bool free_code_to_execute;  //!< Free the pointer if set to true.
};

/**
 * @brief
 * Gets the memory access as string.
 * @param type The type of the memory access.
 * @return The access string.
 */
static const char* get_memory_access_as_string(uc_mem_type type)
{
    switch (type)
    {
        case UC_MEM_READ_AFTER:
        case UC_MEM_READ:
            return "read [mapped]";
        case UC_MEM_WRITE:
            return "write [mapped]";
        case UC_MEM_FETCH:
            return "fetch [mapped]";
        case UC_MEM_READ_UNMAPPED:
            return "read [unmapped]";
        case UC_MEM_WRITE_UNMAPPED:
            return "write [unmapped]";
        case UC_MEM_FETCH_UNMAPPED:
            return "fetch [unmapped]";
        case UC_MEM_READ_PROT:
            return "read [protected]";
        case UC_MEM_WRITE_PROT:
            return "write [protected]";
        case UC_MEM_FETCH_PROT:
            return "fetch [protected]";
        default:
            break;
    }

    return "unknown";
}

/**
 * @brief
 * Callback for executing a code block.
 * @param uc Unicorn instance.
 * @param address The address of the block.
 * @param size The block size.
 * @param user_data A user provided pointer.
 */
static void hook_block(uc_engine* uc, uint64_t address, uint32_t size,
                       void* user_data)
{
    LOG_INFO("Block address: " HEX_ADDR_64 ", size: " HEX_ADDR_32 "\n", address,
             size);

    UNUSED(uc);
    UNUSED(address);
    UNUSED(size);
    UNUSED(user_data);
}

/**
 * @brief
 * Callback for executing code.
 * @param uc Unicorn instance.
 * @param address The address of the execution code.
 * @param size The size of the execution instruction.
 * @param user_data A user provided pointer.
 */
static void hook_code(uc_engine* uc, uint64_t address, uint32_t size,
                      void* user_data)
{
    LOG_INFO("Instruction address: " HEX_ADDR_64 ", size: " HEX_ADDR_32 "\n",
             address, size);

    UNUSED(uc);
    UNUSED(address);
    UNUSED(size);
    UNUSED(user_data);
}

/**
 * @brief Generic function to log memory access events.
 * @param uc Unicorn instance that triggered the hook.
 * @param type The type of the memory access.
 * @param address Address where the code is being executed.
 * @param size Size of data being read or written.
 * @param value Value of data being written to memory, ignore otherwise.
 * @param user_data A user provided pointer.
 */
static void memory_access(uc_engine* uc, uc_mem_type type, uint64_t address,
                          int32_t access_size, int64_t value, void* user_data)
{
    LOG_INFO("Memory access: %s, address: " HEX_ADDR_64 ", size: " HEX_ADDR_32
             ", value: " HEX_ADDR_64 "\n",
             get_memory_access_as_string(type), address, access_size, value);

    UNUSED(uc);
    UNUSED(type);
    UNUSED(address);
    UNUSED(access_size);
    UNUSED(value);
    UNUSED(user_data);
}

/**
 * @brief Callback function for handling protected memory access events.
 * @param uc Unicorn instance that triggered the hook.
 * @param type The type of the memory access.
 * @param address Address where the code is being executed.
 * @param size Size of data being read or written.
 * @param value Value of data being written to memory, ignore otherwise.
 * @param user_data A user provided pointer.
 * @return return true to continue, or false to stop program.
 */
static bool hook_protected_memory_access(uc_engine* uc, uc_mem_type type,
                                         uint64_t address, int32_t access_size,
                                         int64_t value, void* user_data)
{
    memory_access(uc, type, address, access_size, value, user_data);

    return false;
}

/**
 * @brief Callback function for handling unmapped memory access events.
 * @param uc Unicorn instance that triggered the hook.
 * @param type The type of the memory access.
 * @param address Address where the code is being executed.
 * @param size Size of data being read or written.
 * @param value Value of data being written to memory, ignore otherwise.
 * @param user_data A user provided pointer.
 * @return return true to continue, or false to stop program.
 */
static bool hook_unmapped_memory_access(uc_engine* uc, uc_mem_type type,
                                        uint64_t address, int32_t access_size,
                                        int64_t value, void* user_data)
{
    memory_access(uc, type, address, access_size, value, user_data);

    return false;
}

/**
 * @brief Callback function for handling memory access events.
 * @param uc Unicorn instance that triggered the hook.
 * @param type The type of the memory access.
 * @param address Address where the code is being executed.
 * @param size Size of data being read or written.
 * @param value Value of data being written to memory, ignore otherwise.
 * @param user_data A user provided pointer.
 */
static void hook_valid_memory_access(uc_engine* uc, uc_mem_type type,
                                     uint64_t address, int32_t access_size,
                                     int64_t value, void* user_data)
{
    memory_access(uc, type, address, access_size, value, user_data);
}

/**
 * @brief Callback function for handling interrupts and syscall events.
 * @param uc Unicorn instance that triggered the hook.
 * @param interrupt_number The interrupt or syscall that triggered the hook.
 * @param user_data A user provided pointer.
 */
static void hook_interrupt(uc_engine* uc, uint32_t interrupt_number,
                           void* user_data)
{
    LOG_INFO("Interrupt: " HEX_ADDR_32 "\n", interrupt_number);

    UNUSED(uc);
    UNUSED(interrupt_number);
    UNUSED(user_data);
}

/**
 * @brief Callback function for handling invalid instructions.
 * @param uc Unicorn instance that triggered the hook.
 * @param user_data A user provided pointer.
 * @return True to continue the execution, else false.
 */
static bool hook_invalid_instruction(uc_engine* uc, void* user_data)
{
    LOG_INFO("Invalid instruction\n");

    UNUSED(uc);
    UNUSED(user_data);

    return false;
}

/**
 * @brief
 * Reads a file with given in given @p mode.
 * @param filename The filename to read from.
 * @param mode The mode to open the file.
 * @param buffer A buffer that will be allocated to read the file in.
 * @param size The allocated bytes of the buffer.
 * @return 0 on success, else an error code.
 */
static int read_binary_file(const char* filename, const char* mode,
                            char** buffer, size_t* size)
{
    if (buffer == NULL || size == NULL)
    {
        return -EFAULT;
    }

    FILE* file_stream = fopen(filename, mode);

    if (file_stream == NULL)
    {
        return -errno;
    }

    const int64_t begin = ftell(file_stream);
    int ret = fseek(file_stream, 0, SEEK_END);

    if (ret != 0)
    {
        ret = ferror(file_stream);
        fclose(file_stream);

        return ret;
    }

    const int64_t end = ftell(file_stream);
    *size = (size_t)(end - begin);

    if (size > 0)
    {
        *buffer = (char*)malloc(*size);
        ret = fseek(file_stream, 0, SEEK_SET);

        if (ret != 0)
        {
            ret = ferror(file_stream);
            fclose(file_stream);
            free(*buffer);
            *buffer = NULL;
            *size = 0;

            return ret;
        }

        const size_t read_bytes = fread(*buffer, 1, *size, file_stream);

        if (read_bytes != *size)
        {
            ret = fclose(file_stream);
            free(*buffer);
            *buffer = NULL;
            *size = 0;

            return ret;
        }
    }

    ret = fclose(file_stream);

    return ret;
}

/**
 * @brief
 * Maps memory for the emulation.
 * @param config The instance containing the configuration.
 * @param memory The memory details to map.
 */
static void map_memory(struct Playground_config* config, struct Memory* memory)
{
    LOG_INFO("Map memory %s, address: " HEX_ADDR_64 ", size: " HEX_ADDR_64
             ", permission: " HEX_ADDR_32 "\n",
             memory->name, memory->address, memory->size, memory->permission);

    const uc_err error_code = uc_mem_map(config->uc, memory->address,
                                         memory->size, memory->permission);
    ENSURE_UC(error_code, "uc_mem_map() failed\n");
}

/**
 * @brief
 * Sync and update the programm counter value.
 * This method is peridically called after each emulation step.
 * @param config The configuration to be updated.
 */
static void update_pc(struct Playground_config* config)
{
    size_t register_size = sizeof(config->pc);
    uc_err error_code =
        uc_reg_read2(config->uc, config->pc_reg, &config->pc, &register_size);
    ENSURE_UC(error_code, "uc_reg_read2() failed\n");

    register_size = sizeof(config->sp);
    error_code =
        uc_reg_read2(config->uc, config->sp_reg, &config->sp, &register_size);
    ENSURE_UC(error_code, "uc_reg_read2() failed\n");
}

/**
 * @brief
 * Initializes registers for the emulation.
 * @param config The configuration to be updated.
 */
static void init_registers(struct Playground_config* config)
{
    LOG_INFO("Initialize registers\n");

    size_t register_size = sizeof(config->pc);
    uc_err error_code =
        uc_reg_write2(config->uc, config->pc_reg, &config->pc, &register_size);
    ENSURE_UC(error_code, "uc_reg_write2() failed\n");

    register_size = sizeof(config->sp);
    error_code =
        uc_reg_write2(config->uc, config->sp_reg, &config->sp, &register_size);
    ENSURE_UC(error_code, "uc_reg_write2() failed\n");
}

/**
 * @brief
 * Initializes memory for the emulation.
 * @param config The configuration to be updated.
 */
static void init_memory(struct Playground_config* config)
{
    LOG_INFO("Initialize memory\n");

    for (size_t index = 0; index < config->memory_config.count; ++index)
    {
        map_memory(config, &config->memory_config.memory[index]);
    }

    // write instructions to the memory
    struct Memory* base = config->memory_config.base;
    uc_err error_code = uc_mem_write(
        config->uc, base->address, config->code_to_execute, config->code_size);
    ENSURE_UC(error_code, "uc_mem_write() failed\n");
}

/**
 * @brief
 * Initializes the hooks used for the emulation.
 * @param config The configuration to be updated.
 */
static void init_hooks(struct Playground_config* config)
{
    LOG_INFO("Initialize hooks\n");

    // tracing all basic blocks
    uc_hook trace_block = 0;
    uc_err error_code = uc_hook_add(config->uc, &trace_block, UC_HOOK_BLOCK,
                                    hook_block, config, 1, 0);
    ENSURE_UC(error_code, "uc_hook_add() failed\n");

    // tracing one instruction
    uc_hook trace_code = 0;
    error_code = uc_hook_add(config->uc, &trace_code, UC_HOOK_CODE, hook_code,
                             config, 1, 0);
    ENSURE_UC(error_code, "uc_hook_add() failed\n");

    // tracing interrupt or syscalls
    uc_hook trace_interrupt = 0;
    error_code = uc_hook_add(config->uc, &trace_interrupt, UC_HOOK_INTR,
                             hook_interrupt, config, 1, 0);
    ENSURE_UC(error_code, "uc_hook_add() failed\n");

    // tracing invalid instructions
    uc_hook trace_invalid_instruction = 0;
    error_code = uc_hook_add(config->uc, &trace_invalid_instruction,
                             UC_HOOK_INSN_INVALID, hook_invalid_instruction,
                             config, 1, 0);
    ENSURE_UC(error_code, "uc_hook_add() failed\n");

    // tracing unmapped memory access
    const int32_t unmapped_memory_access[] = {
        UC_HOOK_MEM_READ_UNMAPPED,
        UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_HOOK_MEM_FETCH_UNMAPPED,
    };

    // tracing protected memory access
    const int32_t protected_memory_access[] = {
        UC_HOOK_MEM_READ_PROT,
        UC_HOOK_MEM_WRITE_PROT,
        UC_HOOK_MEM_FETCH_PROT,
    };

    // tracing valid memory access
    const int32_t valid_memory_access[] = {
        UC_HOOK_MEM_READ,
        UC_HOOK_MEM_WRITE,
        UC_HOOK_MEM_FETCH,
    };

    const size_t unmapped_memory_size = sizeof(unmapped_memory_access);
    const size_t protected_memory_size = sizeof(protected_memory_access);
    const size_t valid_memory_size = sizeof(valid_memory_access);

    ENSURE(unmapped_memory_size == protected_memory_size &&
               protected_memory_size == valid_memory_size,
           EINVAL,
           "Incorrect number of arguments: " HEX_ADDR_64 " " HEX_ADDR_64
           " " HEX_ADDR_64 "\n",
           unmapped_memory_size, protected_memory_size, valid_memory_size);

    const size_t invalid_memory_hook_count =
        sizeof(unmapped_memory_access) / sizeof(unmapped_memory_access[0]);

    for (size_t index = 0; index < invalid_memory_hook_count; ++index)
    {
        uc_hook trace_memory_access = 0;
        error_code = uc_hook_add(config->uc, &trace_memory_access,
                                 unmapped_memory_access[index],
                                 hook_unmapped_memory_access, config, 1, 0);
        ENSURE_UC(error_code, "uc_hook_add() for %" PRIi64 " failed\n", index);

        error_code = uc_hook_add(config->uc, &trace_memory_access,
                                 protected_memory_access[index],
                                 hook_protected_memory_access, config, 1, 0);
        ENSURE_UC(error_code, "uc_hook_add() for %" PRIi64 " failed\n", index);

        error_code = uc_hook_add(config->uc, &trace_memory_access,
                                 valid_memory_access[index],
                                 hook_valid_memory_access, config, 1, 0);
        ENSURE_UC(error_code, "uc_hook_add() for %" PRIi64 " failed\n", index);
    }
}

/**
 * @brief
 * Add the memory config to @p config.
 * @param config The configuration to be updated.
 * @param memory The memory to be add.
 */
static void add_memory_config(struct Playground_config* config,
                              struct Memory* memory)
{
    LOG_INFO("Add memory configuration: %s\n", memory->name);

    const size_t max_count =
        sizeof(config->memory_config.memory) / sizeof(struct Memory);

    ENSURE(config->memory_config.count < max_count, ENOMEM,
           "Buffer overflow"
           " - increase the array size\n");

    config->memory_config.memory[config->memory_config.count] = *memory;
    ++config->memory_config.count;
}

/**
 * @brief
 * Prepares and get the configuration to be used for the emulation.
 * @return The configuration, must be freed with free.
 */
static struct Playground_config* get_config()
{
    LOG_INFO("Get the playground configuration\n");

    struct Memory memory[] = {
        {
            .address = 0x8000000,
            .name = "ram",
            .permission = UC_PROT_ALL,
            .size = 2 * 1024 * 1024,
        },
        {
            .address = 0x200000,
            .name = "stack",
            .permission = UC_PROT_ALL,
            .size = 64 * 1024,
        },
    };

    struct Playground_config* config =
        calloc(1, sizeof(struct Playground_config));

    config->cpu_architecture = UC_ARCH_ARM;
    config->cpu_mode = UC_MODE_THUMB;
    config->pc_reg = UC_ARM_REG_PC;
    config->sp_reg = UC_ARM_REG_SP;
    config->pc = memory[0].address;
    config->sp = memory[1].address + memory[1].size - 0x100;

    const size_t memory_count = sizeof(memory) / sizeof(memory[0]);

    for (size_t index = 0; index < memory_count; ++index)
    {
        add_memory_config(config, &memory[index]);
    }

    config->memory_config.base = &config->memory_config.memory[0];

    return config;
}

/**
 * @brief
 * Initializes unicorn and reads in the binary.
 * @param config The configuration to be useds.
 */
static void init_config(struct Playground_config* config)
{
    // initialize unicorn
    const uc_err error_code =
        uc_open(config->cpu_architecture, config->cpu_mode, &config->uc);
    ENSURE_UC(error_code, "uc_open() failed\n");

    ENSURE(config->code_size <= config->memory_config.base->size, ENOMEM,
           "Code does not fit in memory " HEX_ADDR_64 " (" HEX_ADDR_64 ")\n",
           config->code_size, config->memory_config.base->size);
}

/**
 * @brief
 * Frees allocated memory from @p config.
 * @param config The configuration to be used.
 */
static void free_config(struct Playground_config** config)
{
    // clear allocated resources
    const uc_err error_code = uc_close((*config)->uc);
    ENSURE_UC(error_code, "uc_close() failed\n");

    if ((*config)->free_code_to_execute)
    {
        free((*config)->code_to_execute);
    }

    free(*config);
    *config = NULL;
}

/**
 * @brief
 * Executes the code from @p config.
 * @param config The configuration to be used.
 */
static void execute_code_loop(struct Playground_config* config)
{
    uint64_t index = 0;

    LOG_INFO("Start emulation at " HEX_ADDR_64 ".\n", config->pc);

    while (true)
    {
        uc_err error_code = uc_emu_start(config->uc, config->pc,
                                         config->pc + config->code_size, 0, 1);
        ENSURE_UC(error_code, "uc_emu_start() failed\n");
        update_pc(config);
        ++index;

        if (index == UINT64_MAX)
        {
            LOG_INFO("index overflow -> infinite loop?\n");
            break;
        }
    }

    LOG_INFO("Emulation has ended at " HEX_ADDR_64 ".\n", config->pc);
}

/**
 * @brief
 * Initializes code to execute.
 * @param config The configuration to be used.
 * @param argc The argument count in the argument vector.
 * @param argv The argument vector.
 */
void init_code(struct Playground_config* config, int argc, char** argv)
{
    if (argc == 2)
    {
        // If an argument is provided, parse it as filename.
        const char* filename = argv[1];
        ENSURE(strlen(filename) > 0, -1, "no filename set\n");

        // read the binary
        LOG_INFO("Read binary file: %s\n", filename);
        int result = read_binary_file(filename, "rb", &config->code_to_execute,
                                      &config->code_size);
        ENSURE(result == 0, result, "Could not read file\n");
    }
    else
    {
        // execute some instructions to debug on - replace with valid values
        static char code_to_emulate[] = {0xFF, 0xFF, 0xFF, 0xFF};

        config->code_to_execute = code_to_emulate;
        config->code_size = sizeof(code_to_emulate);
    }

    ENSURE(config->code_to_execute != NULL && config->code_size > 0, ENOMEM,
           "Nothing to execute\n");
}

int main(int argc, char** argv)
{
    LOG_INFO("Playground for analyzing the code execution\n");

    struct Playground_config* config = get_config();

    init_code(config, argc, argv);
    init_config(config);
    init_registers(config);
    init_memory(config);
    init_hooks(config);
    execute_code_loop(config);
    free_config(&config);

    return 0;
}
