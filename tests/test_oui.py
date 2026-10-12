"""Vendor MAC prefix table and its generator (exact IEEE organization names)."""

import importlib.util
import os
from pathlib import Path

import pytest

from shimlib import oui

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("gen_oui", ROOT / "tools" / "gen_oui.py")
gen_oui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen_oui)

HEADER = "Registry,Assignment,Organization Name,Organization Address\n"


def test_known_prefixes_and_longest_match():
    assert oui.vendor("EC:71:DB:B6:19:A3") == "Reolink"
    assert oui.vendor("bc325f000051") == "Dahua"
    assert oui.vendor("EC-71-DB-00-00-01") == "Reolink"
    seven = next(p for p in oui.PREFIXES if len(p) == 7)
    assert oui.vendor(seven + "0" * 5) == oui.PREFIXES[seven]
    for bad in (None, "", "zz", "EC71DB", "EC71DBB619A3FF"):
        assert oui.vendor(bad) is None
    assert oui.vendor("001122334455") is None


def test_table_covers_every_brand_and_excludes_tp_link():
    assert set(oui.PREFIXES.values()) == set(gen_oui.BRANDS)
    assert "TP-Link" not in gen_oui.BRANDS
    assert all(len(p) in (6, 7, 9) for p in oui.PREFIXES)
    assert oui.REGISTRY_DATE.count("-") == 2


def write_registry(tmp_path, rows):
    for name in gen_oui.FILES:
        (tmp_path / name).write_text(HEADER)
    with open(tmp_path / "oui.csv", "a") as out:
        out.writelines(f'{reg},{prefix},"{org}","x"\n' for reg, prefix, org in rows)


def test_generator_matches_exact_names_only(tmp_path):
    brands = {
        "Reolink": ["Reolink Innovation Limited"],
        "Dahua": ["Zhejiang Dahua Technology Co., Ltd."],
    }
    rows = [
        ("MA-L", "EC71DB", "Reolink Innovation Limited"),
        ("MA-L", "BC325F", "ZHEJIANG DAHUA TECHNOLOGY CO.,LTD."),  # case/punctuation variant
        ("MA-M", "AABBCC1", "Shanghai Dahua Scale Factory"),  # substring match must not count
        ("MA-L", "112233", "TP-LINK TECHNOLOGIES CO.,LTD."),
        ("MA-L", "445566", "Reolink Innovation Limited Holdings"),
    ]
    write_registry(tmp_path, rows)
    original = gen_oui.BRANDS
    gen_oui.BRANDS = brands
    try:
        prefixes = gen_oui.collect(str(tmp_path))
    finally:
        gen_oui.BRANDS = original
    assert prefixes == {"EC71DB": "Reolink", "BC325F": "Dahua"}


def test_generator_fails_when_a_brand_disappears(tmp_path):
    write_registry(tmp_path, [("MA-L", "EC71DB", "Reolink Innovation Limited")])
    with pytest.raises(SystemExit, match="no registry entries"):
        gen_oui.collect(str(tmp_path))


def test_rendered_module_is_deterministic(tmp_path):
    prefixes = {"EC71DB": "Reolink", "BC325F": "Dahua", "50FACB9": "Bosch"}
    text = gen_oui.render(prefixes, "2026-10-11")
    assert text == gen_oui.render(dict(reversed(list(prefixes.items()))), "2026-10-11")
    namespace = {}
    exec(compile(text, "oui_test", "exec"), namespace)
    assert namespace["vendor"]("50:FA:CB:9A:BC:DE") == "Bosch"


@pytest.mark.skipif(not os.environ.get("IEEE_OUI_DIR"), reason="set IEEE_OUI_DIR to verify")
def test_shipped_table_matches_registry(tmp_path):
    out = tmp_path / "oui.py"
    gen_oui.main(["--registry", os.environ["IEEE_OUI_DIR"], "--date", oui.REGISTRY_DATE,
                  "--out", str(out)])  # fmt: skip
    assert out.read_text() == (ROOT / "shimlib" / "oui.py").read_text()
