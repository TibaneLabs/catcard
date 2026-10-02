/* The memory of one CatCard app (docs/APPS.md).
 *
 * The app area on mk4/mk5/Q1: 256 KiB at 0x2004_0000, the largest aligned power-of-two
 * block of the RAM the firmware does not link (catcard-fw `apps::ARENA`). An app is
 * linked to run there and nowhere else; one runs at a time, so nothing is relocated.
 *
 * Layout, low to high:
 *   header   eight words the loader reads (below)
 *   .text    code
 *   .rodata  constants -- with .text, the code region: read-only and executable
 *   .data    starts at the next power of two from the base, so the MPU can give code and
 *            data different permissions with one region each (ARMv7-M ARM §B3.5.9: a
 *            region is a power of two, aligned to itself)
 *   .bss     zeroed by the loader
 *   stack    the rest of the area, down from its top
 */
MEMORY
{
  APP : ORIGIN = 0x20040000, LENGTH = 256K
}

ENTRY(_start)

SECTIONS
{
  .app_header ORIGIN(APP) :
  {
    LONG(0x50504143)   /* "CAPP" */
    LONG(1)            /* header version */
    LONG(_start)       /* entry, Thumb bit set */
    LONG(__code_end)
    LONG(__data_start)
    LONG(__data_end)
    LONG(__bss_end)
    LONG(0)            /* kernel build ID: phase 2 */
  } > APP

  .text : { *(.text .text.*) } > APP

  .rodata : ALIGN(4)
  {
    *(.rodata .rodata.*)
    . = ALIGN(4);
    __code_end = .;
  } > APP

  .data ORIGIN(APP) + (1 << LOG2CEIL(__code_end - ORIGIN(APP))) : ALIGN(4)
  {
    __data_start = .;
    *(.data .data.*)
    . = ALIGN(4);
    __data_end = .;
  } > APP

  .bss (NOLOAD) : ALIGN(4)
  {
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(4);
    __bss_end = .;
  } > APP

  /DISCARD/ : { *(.ARM.exidx .ARM.exidx.*) *(.ARM.extab .ARM.extab.*) }
}
