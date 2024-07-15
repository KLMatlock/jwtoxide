=================
API Documentation
=================

.. automodule:: jwtoxide

   .. autofunction:: encode
   .. autofunction:: decode

   .. autoclass:: ValidationOptions
      :members:

   .. autoclass:: DecodingKey
      :members:

   .. autoclass:: EncodingKey
      :members:

JSON Web Keys (JWKs)
====================

   .. autoclass:: Jwk
      :members:
   
   .. autoclass:: JwkSet
      :members:

   .. autoclass:: KeyRing
      :members:

Exceptions
==========

   .. autoclass:: InvalidTokenError
   .. autoclass:: DecodeError
   .. autoclass:: InvalidSignatureError
   .. autoclass:: MissingRequiredClaimError
   .. autoclass:: ExpiredSignatureError
   .. autoclass:: InvalidIssuerError
   .. autoclass:: InvalidAudienceError
   .. autoclass:: InvalidSubjectError
   .. autoclass:: ImmatureSignatureError
   .. autoclass:: InvalidAlgorithmError

