from .utils import save_json, make_snapshot_filename

def export_snapshot(report, outpath=None):
    if outpath:
        save_json(report, outpath)
        return outpath
    fn = make_snapshot_filename(report.get("domain", "unknown"))
    save_json(report, fn)
    return fn
