/* mock_helper.c -- mock helper for bash plugin UT. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "mock_helper.h"

/* define test scenarios for mock functions return different value by scenario. */
int test_scenario;

/* define memory allocate counter. */
int memory_allocate_count;

/* Set test scenario for test*/
void set_test_scenario(int scenario)
{
    test_scenario = scenario;
}

/* Get test scenario for test*/
int get_test_scenario()
{
    return test_scenario;
}

/* Set memory allocate count for test*/
void set_memory_allocate_count(int count)
{
    memory_allocate_count = count;
}

/* Get memory allocate count for test*/
int get_memory_allocate_count()
{
    return memory_allocate_count;
}


/* MOCK malloc method*/
void *mock_malloc(size_t size)
{
    memory_allocate_count++;
    debug_printf("MOCK: malloc %ld bytes memory count: %d\n", size, memory_allocate_count);
    return malloc(size);
}

/* MOCK free method*/
void mock_free(void* ptr)
{
    memory_allocate_count--;
    debug_printf("MOCK: free memory count: %d\n", memory_allocate_count);
    free(ptr);
}