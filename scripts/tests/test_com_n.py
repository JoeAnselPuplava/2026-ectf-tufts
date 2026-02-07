# tests for listen command
import test_common


import time
from loguru import logger


def listen():
   cmd = "uvx ectf tools listen"


   if VERBOSE:
       logger.info(cmd)


   env = os.environ
   env["LOGURU_COLORIZE"] = "NO"
  
   res = subprocess.run(cmd,
                        timeout=1
                        capture_output=True,
                        text=True,
                        env=env)
  
   if VERBOSE:
       logger.info(res)


   return res


#
def success_listen(suppress_output=False):
   res = listen()


   logs = res.stdout
   msg = ""


   test_common.check_result(
       msg,
       logs,
       "success_listen"
   )


   if not suppress_output:
       logger.success(f"success_listen - passed")


