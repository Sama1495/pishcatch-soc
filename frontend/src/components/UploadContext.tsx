import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, uploadBatch, uploadEml } from "../services/api";
import { useToast } from "./Toasts";

interface UploadApi {
  busy: boolean;
  openPicker: () => void;
  takeFiles: (files: File[] | FileList | undefined) => void;
}

const UploadContext = createContext<UploadApi | null>(null);

function allowed(file: File): boolean {
  const name = file.name.toLowerCase();
  return name.endsWith(".eml") || name.endsWith(".mbox");
}

export function UploadProvider({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const toast = useToast();
  const inputRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  const takeFiles = useCallback(
    (input: File[] | FileList | undefined) => {
      const files = input ? Array.from(input) : [];
      if (!files.length || busy) return;
      if (files.every((file) => !allowed(file))) {
        toast("Only a .eml or .mbox file can be analyzed.");
        return;
      }
      setBusy(true);
      const run =
        files.length === 1 && files[0].name.toLowerCase().endsWith(".eml")
          ? uploadEml(files[0]).then((created) => {
              toast("Analysis stored. Nothing was fetched or executed.");
              navigate(`/incidents/${created.incident_id}`);
            })
          : uploadBatch(files.filter(allowed)).then((batch) => {
              const first = batch.items.find((item) => item.incident_id);
              toast(`Batch: ${batch.accepted} analyzed, ${batch.failed} failed. Nothing was executed.`);
              if (first?.incident_id) navigate(`/incidents/${first.incident_id}`);
            });
      run
        .catch((error: unknown) => {
          toast(error instanceof ApiError ? error.message : "Upload failed.");
        })
        .finally(() => setBusy(false));
    },
    [busy, navigate, toast],
  );

  const value = useMemo<UploadApi>(
    () => ({
      busy,
      openPicker: () => inputRef.current?.click(),
      takeFiles,
    }),
    [busy, takeFiles],
  );

  return (
    <UploadContext.Provider value={value}>
      <div
        className={dragOver ? "drop-root drag-over" : "drop-root"}
        onDragEnter={(event) => {
          event.preventDefault();
          setDragOver(true);
        }}
        onDragOver={(event) => {
          event.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={(event) => {
          if (event.currentTarget === event.target) setDragOver(false);
        }}
        onDrop={(event) => {
          event.preventDefault();
          setDragOver(false);
          takeFiles(event.dataTransfer.files);
        }}
      >
        {children}
        {dragOver && <div className="drop-veil">Drop the mail to analyze it</div>}
        {busy && <div className="drop-veil">FishBot is reading the message…</div>}
      </div>
      <input
        ref={inputRef}
        className="sr-only"
        type="file"
        accept=".eml,.mbox,message/rfc822,application/mbox"
        multiple
        onChange={(event) => {
          takeFiles(event.target.files ?? undefined);
          event.target.value = "";
        }}
      />
    </UploadContext.Provider>
  );
}

export function useUpload(): UploadApi {
  const value = useContext(UploadContext);
  if (!value) throw new Error("Upload is unavailable.");
  return value;
}
