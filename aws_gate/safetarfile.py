import sys

from tarfile import TarFile
from os.path import abspath, realpath, dirname, join as joinpath

_resolved = lambda x: realpath(abspath(x))


def _badpath(path, base):
    # joinpath will ignore base if path is absolute
    return not _resolved(joinpath(base, path)).startswith(base)


def _badlink(info, base):
    # Links are interpreted relative to the directory containing the link
    tip = _resolved(joinpath(base, dirname(info.name)))
    return _badpath(info.linkname, base=tip)


class TarInfoException(Exception):
    pass


class SafeTarFile(TarFile):
    @classmethod
    def open(cls, *args, **kwargs):
        cls._base = _resolved(".")
        return super().open(*args, **kwargs)

    def _is_sanitize_member(self, tarinfo):
        if _badpath(tarinfo.name, self._base):
            raise TarInfoException(f"{tarinfo.name} is blocked (illegal path)")

        if tarinfo.issym() and _badlink(tarinfo, self._base):
            raise TarInfoException(
                f"{tarinfo.name} is blocked: Hard link to {tarinfo.linkname}"
            )
        if tarinfo.islnk() and _badlink(tarinfo, self._base):
            raise TarInfoException(
                f"{tarinfo.name} is blocked: Symlink to {tarinfo.linkname}"
            )

    def _extract_member(self, tarinfo, *args, **kwargs):
        try:
            self._is_sanitize_member(tarinfo)
            super()._extract_member(tarinfo, *args, **kwargs)
        except TarInfoException as e:
            print(str(e), file=sys.stderr)
