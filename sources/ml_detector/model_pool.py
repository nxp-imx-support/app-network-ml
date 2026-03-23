# -*- coding: utf-8 -*-
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause

class ModelPool:
    """Registry for managing multiple DDoS detection models"""

    def __init__(self):
        self._models = {}
        self._active_model = None

    def register(self, model_id, model_instance):
        """Register a model in the pool"""
        self._models[model_id] = model_instance

    def get_model(self, model_id):
        """Get a model by ID"""
        return self._models.get(model_id)

    def set_active(self, model_id):
        """Set the active model for inference"""
        if model_id not in self._models:
            raise ValueError(f"Model {model_id} not found in pool")
        self._active_model = model_id

    def get_active_model(self):
        """Get the currently active model"""
        if self._active_model is None:
            raise ValueError("No active model set")
        return self._models[self._active_model]

    def list_models(self):
        """List all registered models"""
        return list(self._models.keys())

