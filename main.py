import os
import sys
from argparse import ArgumentParser

from PyQt6.QtCore import QLockFile, QDir
from PyQt6.QtWidgets import QApplication

from common.consts import APP_NAME
from dispatchers.runner import CoreDispatcher


def main(args):
    # Cross-platform lock file path (inside temp directory)
    # lockfile_path = os.path.join(QDir.tempPath(), f"{APP_NAME}.lock")
    # lockfile = QLockFile(lockfile_path)
    #
    # if not lockfile.tryLock(100):  # Wait up to 100ms for the lock
    #     print("App is already running.")
    #     sys.exit(183)

    app = QApplication([APP_NAME] + [str(v) for k, v in vars(args).items()])

    try:  # safety measure
        dispatcher = CoreDispatcher(args, app=app)
        dispatcher.start()

    except Exception as e:
        print(e)
        raise e
    finally:
        pass

    sys.exit(app.exec())


def cli():
    parser = ArgumentParser()
    parser.add_argument('-c', '--config', type=str, required=True, help="The path to the main config .json file.")
    parser.add_argument('-l','--log', type=str, default='logs', help="The path to the log directory.")
    return parser.parse_args()


if __name__ == '__main__':
    args = cli()

    main(args)