'''
Created on Mar 1, 2019
@author: Shawn
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import SatConstraints as SatConstraints

from parser.stpcommands import getStringLeftRotate as rotl

class Cipher(AbstractCipher):
    """
    Represents the differential behaviour of sand and can be used
    to find differential characteristics for the given parameters.
    """

    name = "sand_diff_pattern"
    rot_alpha = 0
    rot_beta = 1
    PERM = []

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y',
                "inG0", "inG1",
                "xorG", "permG",
                "sumw",
                ]

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for sand diff pattern with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds   = parameters["rounds"]
        weight   = parameters["sweight"]
        if wordsize == 32:
            self.PERM = [7, 4, 1, 6, 3, 0, 5, 2]
        elif wordsize == 64:
            self.PERM = [14, 15, 8, 9, 2, 3, 12, 13, 6, 7, 0, 1, 10, 11, 4, 5]
        else:
            raise Exception("Wrong wordsize!")

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP: sand diff pattern\n"
                      "% w = {} alpha = {} beta = {}\n"
                      "% rounds = {}\n\n".format(
                        wordsize,
                        self.rot_alpha, self.rot_beta,
                        rounds))
            stp_file.write(header)

            # Setup variables
            # x as left, y as right
            x = ["x{}".format(i) for i in range(rounds + 1)]
            y = ["y{}".format(i) for i in range(rounds + 1)]
            in_G0  = ["inG0{}".format(i) for i in range(rounds)]
            in_G1  = ["inG1{}".format(i) for i in range(rounds)]
            xor_G  = ["xorG{}".format(i) for i in range(rounds)]
            perm_G  = ["permG{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["sumw{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize // 4)
            stpcommands.setupVariables(stp_file, y, wordsize // 4)
            stpcommands.setupVariables(stp_file, in_G0, wordsize // 4)
            stpcommands.setupVariables(stp_file, in_G1, wordsize // 4)
            stpcommands.setupVariables(stp_file, xor_G, wordsize // 4)
            stpcommands.setupVariables(stp_file, perm_G, wordsize // 4)
            stpcommands.setupVariables(stp_file, w, 16)

            stpcommands.setupWeightComputationSum(stp_file, weight, w, 16)

            for i in range(rounds):
                self.setupRound(stp_file,
                                     x[i], y[i],
                                     x[i+1], y[i+1],
                                     in_G0[i], in_G1[i],
                                     xor_G[i], perm_G[i],
                                     w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, [x[0], y[0]], wordsize // 4)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])
                stpcommands.assertVariableValue(stp_file, y[0], y[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize // 4)

            stpcommands.setupQuery(stp_file)

        return

    def setupRound(self,
                        stp_file,
                        x_in, y_in,
                        x_out, y_out,
                        in_G0, in_G1,
                        xor_G, perm_G,
                        w, wordsize):
        """
        Model for differential behaviour of one round
        """
        command = ""

        # 1. y_out = x_in
        command += "ASSERT({} = {});\n".format(y_out, x_in)

        # 2. rotations
        x_in_rotalpha = rotl(x_in, self.rot_alpha, wordsize // 4)
        x_in_rotbeta  = rotl(x_in, self.rot_beta, wordsize // 4)
        command += "ASSERT({} = {});\n".format(in_G0, x_in_rotalpha)
        command += "ASSERT({} = {});\n".format(in_G1, x_in_rotbeta)

        # 3. G0 ^ G1 = xor_G
        command += SatConstraints.PatternXorAssert(
                in_G0, in_G1, xor_G, wordsize // 4)

        # 4. xor_G PERM to perm_G
        for i in range(wordsize // 4):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(
                    perm_G, self.PERM[i], xor_G, i)

        # 5. perm_G ^ y_in = x_out
        command += SatConstraints.PatternXorAssert(
                y_in, perm_G, x_out, wordsize // 4)

        # 6. Weight computation
        sum_w_i = stpcommands.getWeightString([x_in], wordsize // 4, 0, w)
        sum_w_i += '\n'
        command += sum_w_i

        stp_file.write(command)
        return
