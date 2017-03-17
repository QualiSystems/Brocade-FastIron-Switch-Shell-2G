#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import time

BUFFER_READUP_TIMEOUT = 3
BUFFER_READUP_RETRIES = 10


def buffer_readup(output, cli_service, logger, max_retries=BUFFER_READUP_RETRIES, retry_timeout=BUFFER_READUP_TIMEOUT):
    """ Read buffer to end of command execution if prompt returned immediately """
    retries = 1
    while not re.search(r"[Dd]one|[Ee]rror|[Ff]ailed", output, re.DOTALL):
        if retries > max_retries:
            raise Exception("Buffer Readup", "Buffer readup failed with error: TFTP session timeout")

        time.sleep(retry_timeout)
        output += cli_service.send_command(command="", logger=logger)
        retries += 1

    output += cli_service.send_command(command="", logger=logger)

    return output
