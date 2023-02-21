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

import logging
import angr
import claripy
from .plugins import TraceElement

log = logging.getLogger(__name__)


class Breakpoints:
    def setup(self, proj, simgr, layout):
        """Setup the breakpoints for the simulation manager."""
        # Call stack tracking breakpoints
        simgr.active[0].inspect.b(
            "call",
            when=angr.BP_BEFORE,
            action=lambda st: st.enclave.call_stack.append(
                TraceElement(st.project, st.solver.eval(st.inspect.function_address))
            ),
        )
        simgr.active[0].inspect.b(
            "return", when=angr.BP_BEFORE, action=self.delete_last_call_if_exists
        )

        # Trace tracking breakpoint
        simgr.active[0].inspect.b(
            "exit",
            when=angr.BP_AFTER,
            action=lambda st: st.enclave.jump_trace.append(
                TraceElement(st.project, st.solver.eval(st.inspect.exit_target))
            ),
        )

        # Memory tracking
        simgr.active[0].inspect.b(
            "mem_read",
            when=angr.BP_AFTER,
            action=lambda s: self.outside_memory_read_detection(s, layout),
        )
        return proj, simgr

    def outside_memory_read_detection(self, state, layout):
        """Detects when a memory read is outside the enclave and replaces it with an unconstrained value.j"""
        addr = state.inspect.mem_read_address
        assert state.inspect.mem_read_length is not None
        length = state.inspect.mem_read_length
        allowed_range_begin = layout.base_addr
        allowed_range_end = allowed_range_begin + layout.enclave_size - length

        if state.solver.satisfiable(
            extra_constraints=[
                claripy.Or(addr < allowed_range_begin, addr > allowed_range_end)
            ]
        ):
            state.inspect.mem_read_expr = state.solver.Unconstrained(
                "symb_read", length * 8
            )

    def delete_last_call_if_exists(self, state):
        """Deletes the last call from the call stack if it exists."""
        if state.enclave.call_stack is not None and state.enclave.call_stack:
            del state.enclave.call_stack[-1]
