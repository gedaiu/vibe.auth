/++
  A module containing the token structure

  Copyright: © 2018-2020 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/
module vibeauth.token;

import vibeauth.data.token;

/// A user token used to authorize the requests
deprecated("use vibeauth.data.token.Token instead") alias Token = vibeauth.data.token.Token;