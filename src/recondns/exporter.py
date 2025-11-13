from .utils import make_snapshot_filename, save_json


def export_snapshot(report, outpath=None):
    if outpath:
        save_json(report, outpath)
        return outpath
    fn = make_snapshot_filename(report.get("domain", "unknown"))
    save_json(report, fn)
    return fn
