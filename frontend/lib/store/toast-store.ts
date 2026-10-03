import { create } from "zustand";

export interface Toast {
  id: string;
  title: string;
  description?: string;
  type?: "success" | "error" | "info" | "warning";
  duration?: number;
}

interface ToastStore {
  toasts: Toast[];
  addToast: (toast: Omit<Toast, "id">) => void;
  removeToast: (id: string) => void;
}

export const useToastStore = create<ToastStore>((set) => ({
  toasts: [],
  addToast: (toast) => {
    const id = Math.random().toString(36).substring(2, 9);
    set((state) => ({ toasts: [...state.toasts, { ...toast, id }] }));
    setTimeout(() => {
      set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) }));
    }, toast.duration || 4000);
  },
  removeToast: (id) =>
    set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) })),
}));

export const toast = {
  success: (title: string, description?: string) =>
    useToastStore.getState().addToast({ title, description, type: "success" }),
  error: (title: string, description?: string) =>
    useToastStore.getState().addToast({ title, description, type: "error" }),
  info: (title: string, description?: string) =>
    useToastStore.getState().addToast({ title, description, type: "info" }),
  warning: (title: string, description?: string) =>
    useToastStore.getState().addToast({ title, description, type: "warning" }),
};

export const useToast = () => {
  const addToast = (titleOrToast: string | Omit<Toast, "id">, type?: Toast["type"]) => {
    if (typeof titleOrToast === "string") {
      useToastStore.getState().addToast({ title: titleOrToast, type: type || "info" });
    } else {
      useToastStore.getState().addToast(titleOrToast);
    }
  };
  return { addToast };
};

