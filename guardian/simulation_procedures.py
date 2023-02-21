""" Guardian
    Copyright (C) 2021  The Blockhouse Technology Limited (TBTL)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>."""

import logging, sys
import angr, claripy
from .controlstate import ControlState, Rights
import itertools
import collections

log = logging.getLogger(__name__)


class SimEnclu(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self):
        enclu_length_in_bytes = 3
        if self.state.solver.eval(self.state.regs.eax == 0x0):
            log.debug("EREPORT")
            self.successors.add_successor(
                self.state, self.state.addr + enclu_length_in_bytes,
                self.state.solver.true, 'Ijk_Boring')
        elif self.state.solver.eval(self.state.regs.eax == 0x1):
            log.debug("EGETKEY")
            self.successors.add_successor(
                self.state, self.state.addr + enclu_length_in_bytes,
                self.state.solver.true, 'Ijk_Boring')
        elif self.state.solver.eval(self.state.regs.eax == 0x2):
            log.critical("Unexpected EENTER")
            self.exit(1)
        elif self.state.solver.eval(self.state.regs.eax == 0x4):
            log.critical("Unexpected EEXIT")
            self.exit(1)
        else:
            log.critical("Unexpected ENCLU")
            self.exit(1)


class Nop(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        self.successors.add_successor(
            self.state, self.state.addr + kwargs["bytes_to_skip"],
            self.state.solver.true, 'Ijk_Boring')


class Empty(angr.SimProcedure):
    def run(self):
        pass


class UD2(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("UD2 detected! Aborting this branch!")
        log.debug(hex(self.state.addr))
        self.successors.add_successor(self.state, self.state.addr,
                                      self.state.solver.true, 'Ijk_NoHook')
        self.exit(2)


class Rdrand(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        self.state.regs.flags = 1
        self.successors.add_successor(self.state, self.state.addr + 3,
                                      self.state.solver.true, 'Ijk_Boring')


class RegisterEnteringValidation(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### REGISTER ENTERING VALIDATION ###############")
        assert self.state.has_plugin("enclave")
        self.state.enclave.entry_sanitisation_complete = True
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToTrusted(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### TRUSTED ###############")
        assert self.state.has_plugin("enclave")
        self.state.enclave.ooe_rights = Rights.NoReadOrWrite
        self.state.enclave.control_state = ControlState.Trusted
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToExiting(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### EXITING ###############")
        assert self.state.has_plugin("enclave")
        self.state.enclave.ooe_rights = Rights.Write
        self.state.enclave.control_state = ControlState.Exiting
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToExited(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### EXITED ###############")
        assert self.state.has_plugin("enclave")
        self.state.enclave.control_state = ControlState.Exited
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class TransitionToOcall(angr.SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        log.debug("######### OCALL ###############")
        log.debug(hex(self.state.addr))
        assert self.state.has_plugin("enclave")
        self.state.enclave.ooe_rights = Rights.ReadWrite
        self.state.enclave.control_state = ControlState.Ocall
        self.successors.add_successor(self.state, self.state.addr + 0,
                                      self.state.solver.true, 'Ijk_NoHook')


class OcallAbstraction(angr.SimProcedure):
    def run(self, **kwargs):
        log.debug("######### OCALL ABSTRACTION ###############")
        assert self.state.has_plugin("enclave")
        return self.state.solver.Unconstrained("ocall_ret",
                                               self.state.arch.bits)


class malloc(angr.SimProcedure):
    def run(self, sim_size):
        if self.state.solver.symbolic(sim_size):
            log.warning("Allocating size {}\n".format(sim_size))
            size = self.state.solver.max_int(sim_size)
            if size > self.state.libc.max_variable_size:
                log.warning(
                    "Allocation request of %d bytes exceeded maximum of %d bytes; allocating %d bytes",
                    size, self.state.libc.max_variable_size,
                    self.state.libc.max_variable_size)
                size = self.state.libc.max_variable_size
                self.state.add_constraints(sim_size == size)
        else:
            size = self.state.solver.eval(sim_size)
        return self.state.heap._malloc(sim_size)


