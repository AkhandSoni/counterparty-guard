const layer = process.argv[2] ?? 'requested';
console.error(`Unavailable: ${layer} requires Person B's vault/SDK and Person C's end-to-end/demo runner. Person A provides API integration tests and smoke:api; no chain execution or attack success is claimed.`);
process.exitCode = 1;
