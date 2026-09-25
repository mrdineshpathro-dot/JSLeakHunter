from jsleakhunter.parsers import discover_assets, extract_inline
def test_assets(): assert discover_assets('<script src="/a.js"></script>','https://x.test')==['https://x.test/a.js']
def test_inline(): assert extract_inline('<script>const x=1</script>')==['const x=1']
