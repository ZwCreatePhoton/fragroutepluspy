from .mod import Mod

class Echo(Mod):
    name = "echo"
    usage = "echo <string> ..."
    description = """Echo the string argument(s) to standard output."""

    def parse_args(self, args):
        self.message = None

        if len(args) < 1:
            raise Mod.ArgumentException(self)
        self.message = " ".join(args)

    def apply(self, packets):
        print(self.message)
