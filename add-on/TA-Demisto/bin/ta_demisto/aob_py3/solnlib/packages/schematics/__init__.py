# -*- coding: utf-8 -*-

from .models import Model, ModelMeta
from . import types
__version__ = '2.1.0'

# TODO: remove deprecated API
from . import deprecated
deprecated.patch_all()


types.compound.Model = Model
types.compound.ModelMeta = ModelMeta

__all__ = ['Model']
