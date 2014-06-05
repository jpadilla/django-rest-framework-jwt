"""
Test utility to simulate changing the current time, namely overriding utcnow()
"""

import datetime
from datetime import datetime as orig_datetime


SIMTIME = None


def set_simtime(simtime):
    """
    Argument should be a naive utc datetime
    """
    global SIMTIME
    SIMTIME = simtime


def clear_simtime():
    global SIMTIME
    SIMTIME = None


class SimulationDatetimeMeta(type):
    """
    Need to override isinstance(<datetime.datetime obj>, SimulationDatetime) to
    return True
    """
    def __instancecheck__(self, other):
        if isinstance(other, datetime.datetime):
            return True


class SimulationDatetime(datetime.datetime):
    """
    Mock datetime object with patched utcnow() method
    """

    @classmethod
    def utcnow(cls):
        if SIMTIME:
            # assert False, SIMTIME
            return SIMTIME

        return orig_datetime.utcnow()

    __metaclass__ = SimulationDatetimeMeta
